"""Hand-derived priority boundaries, independent of the production calculator."""
import sqlite3
import unittest
from app.services.initial_priority import calculate_initial_priority


class PriorityBoundariesTests(unittest.TestCase):
    def test_requested_boundaries_all_assets_and_modifier_combinations(self):
        connection=sqlite3.connect(':memory:')
        self.addCleanup(connection.close)
        connection.execute('CREATE TABLE mitre_techniques(technique_id TEXT,catalogue_source TEXT)')
        connection.execute("INSERT INTO mitre_techniques VALUES('T1110','taxii')")
        # Columns: Low, Medium, High, Critical asset criticality. Values are
        # independently banded from level adjustments -2/-1/0/+1.
        expected={0:(None,None,None,None),1:('Low','Low','Low','Low'),
            4:('Low','Low','Low','Medium'),5:('Low','Low','Medium','Medium'),
            7:('Medium','Medium','Medium','High'),8:('Medium','Medium','High','High'),
            11:('High','High','High','High'),12:('High','High','Critical','Critical'),
            16:('Critical','Critical','Critical','Critical')}
        raised={'Low':'Medium','Medium':'High','High':'Critical','Critical':'Critical'}
        for level,bases in expected.items():
            for criticality,base in zip(('low','medium','high','critical'),bases):
                for mitre,recurrence in ((False,False),(True,False),(False,True),(True,True)):
                    with self.subTest(level=level,asset=criticality,mitre=mitre,recurrence=recurrence):
                        want=raised[base] if base and (recurrence or (mitre and level>=5)) else base
                        if level<12 and want=='Critical':want='High'
                        result=calculate_initial_priority(dict(rule_level=level,criticality=criticality,
                            occurrences=3 if recurrence else 1,wazuh_mitre_ids=['T1110'] if mitre else [],
                            group_window_minutes=60,firedtimes=999999),connection)
                        self.assertEqual(result.level,want)
                        self.assertLessEqual(result.occurrence_count_used,5)
        for level,asset in ((None,'critical'),(12,None)):
            self.assertIsNone(calculate_initial_priority(dict(rule_level=level,criticality=asset,
                occurrences=3,wazuh_mitre_ids=['T1110'],group_window_minutes=60),connection).level)
