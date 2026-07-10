"""
Tests unitaires — modules/common/concurrency.py

Couvre le helper de parallélisation optionnelle :
  - max_workers=1 : comportement séquentiel strict (ordre, timing)
  - max_workers>1 : exécution réellement concurrente (gain de temps mesuré)
  - préservation de l'ordre des résultats dans les deux modes
  - propagation des exceptions
"""

import time
import threading

import pytest

from modules.common.concurrency import run_concurrent


class TestSequentialMode:

    def test_max_workers_one_preserves_order(self):
        tasks = [(lambda n=i: n) for i in range(10)]
        results = run_concurrent(tasks, max_workers=1)
        assert results == list(range(10))

    def test_max_workers_one_is_truly_sequential(self):
        """Vérifie qu'aucune tâche ne chevauche une autre en mode séquentiel."""
        active = {"count": 0, "max_seen": 0}
        lock = threading.Lock()

        def make_task():
            def task():
                with lock:
                    active["count"] += 1
                    active["max_seen"] = max(active["max_seen"], active["count"])
                time.sleep(0.05)
                with lock:
                    active["count"] -= 1
                return None
            return task

        tasks = [make_task() for _ in range(5)]
        run_concurrent(tasks, max_workers=1)
        assert active["max_seen"] == 1

    def test_empty_task_list(self):
        assert run_concurrent([], max_workers=1) == []
        assert run_concurrent([], max_workers=5) == []


class TestConcurrentMode:

    def test_preserves_input_order_regardless_of_completion_order(self):
        """
        Les tâches complètent dans un ordre potentiellement différent de
        leur soumission (durées différentes) — le résultat final doit
        rester dans l'ordre d'ENTRÉE, pas l'ordre de complétion.
        """
        def make_task(n, sleep_time):
            def task():
                time.sleep(sleep_time)
                return n
            return task

        # La tâche 0 dort le plus longtemps, la tâche 4 le moins —
        # sans préservation d'ordre, la tâche 4 finirait en premier.
        tasks = [make_task(i, 0.2 - i * 0.04) for i in range(5)]
        results = run_concurrent(tasks, max_workers=5)
        assert results == [0, 1, 2, 3, 4]

    def test_actually_runs_concurrently(self):
        """Preuve mesurable : N tâches de durée D en parallèle prennent ~D, pas N×D."""
        tasks = [(lambda: time.sleep(0.15)) for _ in range(5)]

        start = time.time()
        run_concurrent(tasks, max_workers=5)
        elapsed = time.time() - start

        # Séquentiel aurait pris ~0.75s ; parallèle doit être largement sous ce seuil
        assert elapsed < 0.4, f"attendu <0.4s en parallèle, mesuré {elapsed:.2f}s"

    def test_max_workers_limits_concurrent_tasks(self):
        """Avec max_workers=2, jamais plus de 2 tâches actives simultanément."""
        active = {"count": 0, "max_seen": 0}
        lock = threading.Lock()

        def make_task():
            def task():
                with lock:
                    active["count"] += 1
                    active["max_seen"] = max(active["max_seen"], active["count"])
                time.sleep(0.1)
                with lock:
                    active["count"] -= 1
                return None
            return task

        tasks = [make_task() for _ in range(6)]
        run_concurrent(tasks, max_workers=2)
        assert active["max_seen"] <= 2

    def test_results_identical_to_sequential_mode(self):
        """Le CONTENU des résultats doit être identique entre les deux modes, seul le timing change."""
        def make_task(n):
            def task():
                return n * 2
            return task

        tasks_seq = [make_task(i) for i in range(8)]
        tasks_par = [make_task(i) for i in range(8)]

        results_seq = run_concurrent(tasks_seq, max_workers=1)
        results_par = run_concurrent(tasks_par, max_workers=4)

        assert results_seq == results_par == [i * 2 for i in range(8)]


class TestExceptionPropagation:

    def test_exception_in_sequential_mode_propagates(self):
        def failing_task():
            raise ValueError("boom")

        tasks = [(lambda: 1), failing_task]
        with pytest.raises(ValueError, match="boom"):
            run_concurrent(tasks, max_workers=1)

    def test_exception_in_concurrent_mode_propagates(self):
        def failing_task():
            raise ValueError("boom")

        tasks = [(lambda: 1), failing_task, (lambda: 3)]
        with pytest.raises(ValueError, match="boom"):
            run_concurrent(tasks, max_workers=3)
