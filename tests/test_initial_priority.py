"""Versioned initial triage remains distinct from legacy technique weights."""

import sqlite3
import unittest

from app.services.initial_priority import LABELS, VERSION, calculate_initial_priority, priority_rank


class InitialPriorityTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.execute('''CREATE TABLE mitre_techniques(
            technique_id TEXT PRIMARY KEY, catalogue_source TEXT NOT NULL)''')
        self.db.execute('''CREATE TABLE knowledge_base(
            technique_id TEXT PRIMARY KEY, base_risk_score INTEGER NOT NULL)''')
        self.db.executemany('INSERT INTO mitre_techniques VALUES(?,?)',
                            [('T1110', 'project_seed'), ('T1087', 'taxii')])
        self.db.executemany('INSERT INTO knowledge_base VALUES(?,?)',
                            [('T1110', 10), ('T1087', 1)])

    def tearDown(self):
        self.db.close()

    def priority(self, level=6, criticality='medium', occurrences=1, mitre=(), **extra):
        group = {'rule_level': level, 'criticality': criticality,
                 'occurrences': occurrences, 'wazuh_mitre_ids': list(mitre),
                 'group_window_minutes': 60, **extra}
        return calculate_initial_priority(group, self.db)

    def test_supported_wazuh_alert_level_boundaries(self):
        for level, expected in ((0, None), (1, 'Low'), (4, 'Low'),
                                (5, 'Medium'), (7, 'Medium'), (8, 'High'),
                                (11, 'High'), (12, 'Critical'), (16, 'Critical'),
                                (17, None)):
            with self.subTest(level=level):
                self.assertEqual(self.priority(level, 'high').severity_tier, expected)
        self.assertEqual(self.priority(0, 'high').level, None)
        self.assertEqual(self.priority(17, 'high').level, None)
        self.assertEqual(VERSION, 'cdss-initial-priority-v2')

    def test_every_adjacent_asset_criticality_has_ordered_influence(self):
        levels = ('low', 'medium', 'high', 'critical')
        for source_level in range(1, 17):
            scores = [LABELS.index(self.priority(source_level, value).level)
                      for value in levels]
            self.assertEqual(scores, sorted(scores), source_level)
        self.assertEqual((self.priority(6, 'low').level,
                          self.priority(6, 'medium').level), ('Low', 'Medium'))
        self.assertEqual((self.priority(5, 'medium').level,
                          self.priority(5, 'high').level), ('Low', 'Medium'))
        self.assertEqual((self.priority(4, 'high').level,
                          self.priority(4, 'critical').level), ('Low', 'Medium'))
        self.assertEqual(self.priority(11, 'critical').level, 'High')
        self.assertEqual(self.priority(12, 'high').level, 'Critical')

    def test_official_source_mapping_not_legacy_weight_is_eligible(self):
        baseline = self.priority(6, 'medium')
        legacy_high_weight = self.priority(6, 'medium', mitre=('T1110',))
        official_low_weight = self.priority(6, 'medium', mitre=('T1087',))
        self.assertEqual((baseline.level, legacy_high_weight.level), ('Medium', 'Medium'))
        self.assertEqual(legacy_high_weight.mitre_modifier, 0)
        self.assertEqual((official_low_weight.level, official_low_weight.mitre_modifier),
                         ('High', 1))
        self.db.execute("UPDATE knowledge_base SET base_risk_score=10 WHERE technique_id='T1087'")
        self.assertEqual(self.priority(6, 'medium', mitre=('T1087',)), official_low_weight)
        self.db.execute('DROP TABLE knowledge_base')
        self.assertEqual(self.priority(6, 'medium', mitre=('T1087',)), official_low_weight)
        self.assertEqual(self.priority(4, 'critical', mitre=('T1087',)).mitre_modifier, 0)
        self.assertEqual(self.priority(6, 'medium', mitre=('INVALID',)).mitre_modifier, 0)
        self.assertIsNone(self.priority(6, None, mitre=('T1087',)).level)

    def test_mitre_or_recurrence_alone_and_together_add_only_one_tier(self):
        baseline = self.priority()
        mitre = self.priority(mitre=('T1087',))
        recurrence = self.priority(occurrences=3)
        both = self.priority(occurrences=9999, mitre=('T1087',))
        self.assertEqual(baseline.level, 'Medium')
        self.assertEqual((mitre.level, recurrence.level, both.level),
                         ('High', 'High', 'High'))
        self.assertEqual((mitre.mitre_modifier, mitre.recurrence_modifier), (1, 0))
        self.assertEqual((recurrence.mitre_modifier, recurrence.recurrence_modifier), (0, 1))
        self.assertEqual((both.mitre_modifier, both.recurrence_modifier), (1, 1))
        self.assertEqual(both.occurrence_count_used, 5)
        self.assertEqual(self.priority(occurrences=2, firedtimes=9999).level, 'Medium')

    def test_queue_rank_matches_detail_model_for_all_supported_levels(self):
        for level in range(1, 17):
            for criticality in ('low', 'medium', 'high', 'critical'):
                for count in (1, 2, 3, 6):
                    for official in (False, True):
                        with self.subTest(level=level, criticality=criticality,
                                          count=count, official=official):
                            result = self.priority(level, criticality, count,
                                ('T1087',) if official else ())
                            self.assertEqual(priority_rank(level, criticality, count, official),
                                             LABELS.index(result.level))


if __name__ == '__main__':
    unittest.main()
