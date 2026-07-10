"""
Tests unitaires — modules/active/crawler.py

Couvre la découverte de points d'injection :
  - extraction des paramètres de query string
  - extraction des champs de formulaires (GET et POST)
  - exclusion des tokens CSRF connus
  - gestion des erreurs réseau
"""

import pytest
import requests
from unittest.mock import patch, MagicMock
from modules.active.crawler import (
    crawl, _extract_url_params, _extract_form_points, InjectionPoint, refresh_csrf_field,
)


class TestExtractUrlParams:

    def test_single_param(self):
        points = _extract_url_params("http://example.com/search?q=test")
        assert len(points) == 1
        assert points[0].param_name == "q"
        assert points[0].method == "GET"
        assert points[0].param_kind == "url_query"

    def test_multiple_params_each_becomes_own_point(self):
        points = _extract_url_params("http://example.com/page?a=1&b=2&c=3")
        assert len(points) == 3
        names = {p.param_name for p in points}
        assert names == {"a", "b", "c"}

    def test_other_params_preserved_as_context(self):
        points = _extract_url_params("http://example.com/page?a=1&b=2")
        point_a = next(p for p in points if p.param_name == "a")
        assert point_a.other_params == {"b": "2"}

    def test_no_query_string_returns_empty(self):
        assert _extract_url_params("http://example.com/page") == []

    def test_base_url_strips_query_string(self):
        points = _extract_url_params("http://example.com/search?q=test")
        assert points[0].url == "http://example.com/search"


class TestExtractFormPoints:

    def test_get_form_fields_extracted(self):
        html = '''
        <form action="/search" method="get">
          <input type="text" name="q">
        </form>
        '''
        points, n_forms = _extract_form_points(html, "http://example.com/")
        assert n_forms == 1
        assert len(points) == 1
        assert points[0].param_name == "q"
        assert points[0].method == "GET"

    def test_post_form_fields_extracted(self):
        html = '''
        <form action="/comment" method="post">
          <input type="text" name="author" value="Anonymous">
          <textarea name="message"></textarea>
        </form>
        '''
        points, n_forms = _extract_form_points(html, "http://example.com/")
        assert len(points) == 2
        names = {p.param_name for p in points}
        assert names == {"author", "message"}
        assert all(p.method == "POST" for p in points)

    def test_csrf_token_field_excluded(self):
        html = '''
        <form action="/comment" method="post">
          <input type="text" name="message">
          <input type="hidden" name="csrf_token" value="abc123">
        </form>
        '''
        points, _ = _extract_form_points(html, "http://example.com/")
        names = {p.param_name for p in points}
        assert "csrf_token" not in names
        assert "message" in names

    def test_submit_button_not_a_field(self):
        html = '''
        <form action="/x">
          <input type="text" name="q">
          <input type="submit" value="Go">
        </form>
        '''
        points, _ = _extract_form_points(html, "http://example.com/")
        assert len(points) == 1
        assert points[0].param_name == "q"

    def test_file_input_excluded(self):
        html = '''
        <form action="/upload" method="post">
          <input type="file" name="document">
          <input type="text" name="title">
        </form>
        '''
        points, _ = _extract_form_points(html, "http://example.com/")
        names = {p.param_name for p in points}
        assert "document" not in names
        assert "title" in names

    def test_relative_action_resolved_against_base_url(self):
        html = '<form action="/search"><input name="q"></form>'
        points, _ = _extract_form_points(html, "http://example.com/page/sub")
        assert points[0].url == "http://example.com/search"

    def test_empty_action_uses_base_url(self):
        html = '<form action=""><input name="q"></form>'
        points, _ = _extract_form_points(html, "http://example.com/page")
        assert points[0].url == "http://example.com/page"

    def test_no_forms_returns_empty(self):
        points, n_forms = _extract_form_points("<html><body>no forms</body></html>", "http://example.com/")
        assert points == []
        assert n_forms == 0

    def test_default_method_is_get_when_unspecified(self):
        html = '<form action="/x"><input name="q"></form>'
        points, _ = _extract_form_points(html, "http://example.com/")
        assert points[0].method == "GET"

    def test_other_fields_included_in_other_params(self):
        html = '''
        <form action="/comment" method="post">
          <input type="text" name="author" value="Anonymous">
          <input type="text" name="message" value="">
        </form>
        '''
        points, _ = _extract_form_points(html, "http://example.com/")
        author_point = next(p for p in points if p.param_name == "author")
        assert "message" in author_point.other_params


class TestCrawl:

    def test_combines_url_params_and_form_fields(self):
        mock_response = MagicMock()
        mock_response.text = '<form action="/x" method="post"><input name="msg"></form>'
        mock_response.status_code = 200

        mock_session = MagicMock()
        mock_session.get.return_value = mock_response

        result = crawl("http://example.com/page?q=test", session=mock_session)
        param_names = {p.param_name for p in result.injection_points}
        assert "q" in param_names
        assert "msg" in param_names
        assert result.status_code == 200

    def test_network_error_sets_fetch_error(self):
        import requests
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")

        result = crawl("http://example.com/page?q=test", session=mock_session)
        assert result.fetch_error is not None
        # Les params URL restent disponibles même si le fetch HTML échoue
        assert len(result.injection_points) == 1
        assert result.injection_points[0].param_name == "q"

    def test_forms_found_count_reported(self):
        mock_response = MagicMock()
        mock_response.text = '''
            <form action="/a"><input name="x"></form>
            <form action="/b"><input name="y"></form>
        '''
        mock_response.status_code = 200
        mock_session = MagicMock()
        mock_session.get.return_value = mock_response

        result = crawl("http://example.com/", session=mock_session)
        assert result.forms_found == 2


class TestPageUrlTracking:
    """
    Vérifie que page_url (l'URL de la PAGE où le formulaire a été trouvé)
    est correctement peuplé, distinct de `url` (l'action du formulaire)
    quand ils diffèrent — nécessaire pour refresh_csrf_field().
    """

    def test_page_url_matches_base_url_for_same_page_form(self):
        html = '<form action="/submit"><input name="x"></form>'
        points, _ = _extract_form_points(html, "http://example.com/page")
        assert points[0].page_url == "http://example.com/page"
        assert points[0].url == "http://example.com/submit"

    def test_page_url_differs_from_action_url(self):
        html = '<form action="https://other.example.com/api/submit"><input name="x"></form>'
        points, _ = _extract_form_points(html, "http://example.com/contact")
        assert points[0].page_url == "http://example.com/contact"
        assert points[0].url == "https://other.example.com/api/submit"
        assert points[0].page_url != points[0].url


class TestRefreshCsrfField:

    def _make_point_with_csrf(self, page_url="http://x.test/form", csrf_value="stale-token"):
        return InjectionPoint(
            url="http://x.test/submit", method="POST", param_name="message",
            param_kind="form_field",
            other_params={"csrf_token": csrf_value, "author": "test"},
            page_url=page_url,
        )

    def test_returns_none_when_no_csrf_field_present(self):
        point = InjectionPoint(
            url="http://x.test/submit", method="POST", param_name="message",
            param_kind="form_field", other_params={"author": "test"},  # pas de champ CSRF
            page_url="http://x.test/form",
        )
        mock_session = MagicMock()
        result = refresh_csrf_field(point, mock_session, timeout=5, verify=True)
        assert result is None
        mock_session.get.assert_not_called()  # pas d'appel réseau inutile

    def test_returns_none_when_no_page_url(self):
        point = InjectionPoint(
            url="http://x.test/submit", method="POST", param_name="message",
            param_kind="form_field", other_params={"csrf_token": "abc"},
            page_url="",  # pas de page connue à re-fetcher
        )
        mock_session = MagicMock()
        result = refresh_csrf_field(point, mock_session, timeout=5, verify=True)
        assert result is None

    def test_fetches_fresh_value_from_page_url(self):
        point = self._make_point_with_csrf(csrf_value="old-token")
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(
            text='<form><input type="hidden" name="csrf_token" value="fresh-token"></form>',
            status_code=200,
        )

        result = refresh_csrf_field(point, mock_session, timeout=5, verify=True)

        mock_session.get.assert_called_once()
        called_url = mock_session.get.call_args.args[0]
        assert called_url == "http://x.test/form"  # re-fetch la PAGE, pas l'action
        assert result["csrf_token"] == "fresh-token"

    def test_non_csrf_fields_preserved_unchanged(self):
        point = self._make_point_with_csrf(csrf_value="old-token")
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(
            text='<form><input type="hidden" name="csrf_token" value="fresh-token"></form>',
            status_code=200,
        )

        result = refresh_csrf_field(point, mock_session, timeout=5, verify=True)
        assert result["author"] == "test"  # champ non-CSRF intact

    def test_returns_none_on_network_error(self):
        point = self._make_point_with_csrf()
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")

        result = refresh_csrf_field(point, mock_session, timeout=5, verify=True)
        assert result is None

    def test_returns_none_when_field_absent_from_refetched_page(self):
        # La page a changé et ne contient plus le champ CSRF attendu
        point = self._make_point_with_csrf()
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(
            text='<html><body>Page différente, pas de formulaire ici</body></html>',
            status_code=200,
        )

        result = refresh_csrf_field(point, mock_session, timeout=5, verify=True)
        assert result is None

    def test_verify_and_timeout_passed_through(self):
        point = self._make_point_with_csrf()
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(
            text='<input name="csrf_token" value="fresh">', status_code=200,
        )

        refresh_csrf_field(point, mock_session, timeout=15, verify=False)

        call_kwargs = mock_session.get.call_args.kwargs
        assert call_kwargs["timeout"] == 15
        assert call_kwargs["verify"] is False
