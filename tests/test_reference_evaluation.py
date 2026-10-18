"""Frozen draft-reference comparison; never tunes production methodology."""
import copy
from contextlib import closing
import json
import sqlite3
import unittest
from unittest.mock import patch

import reference_evaluation as evaluation


class ReferenceEvaluationTests(unittest.TestCase):
    def test_reference_dataset_and_review_status(self):
        data=evaluation.load_dataset()
        self.assertEqual(len(data['scenarios']),8)
        self.assertEqual(data['label_status'],'draft')
        self.assertTrue(all(s['label_status']=='draft' for s in data['scenarios']))
        self.assertEqual({s['asset_criticality'] for s in data['scenarios']},{'low','medium','high','critical'})

    def test_invalid_reference_labels_rejected(self):
        for label in ('Critical','Unassessed',None,'low'):
            data=evaluation.load_dataset()
            data['scenarios'][0]['reference_priority']=label
            with self.subTest(label=label), patch.object(evaluation.Path,'read_text',return_value=json.dumps(data)):
                with self.assertRaises(ValueError):
                    evaluation.load_dataset()

    def test_fixed_mapping_and_abstention(self):
        self.assertEqual([evaluation.mapped_priority(r) for r in ('low','medium','high','critical',None,'unassessed')],
                         ['Low','Medium','High','High','Unassessed','Unassessed'])
        with self.assertRaises(TypeError):
            evaluation.RISK_TO_REFERENCE['critical']='Low'
        with self.assertRaises(ValueError):
            evaluation.mapped_priority('invented')

    def test_metrics_matrix_orientation_and_no_label_mutation(self):
        rows=[{'reference_priority':'Low','mapped_priority':'Low'},
              {'reference_priority':'High','mapped_priority':'Medium'},
              {'reference_priority':'Medium','mapped_priority':'Unassessed'}]
        original=copy.deepcopy(rows)
        result=evaluation.summarize(rows)
        self.assertEqual((result['assessed'],result['unassessed'],result['exact_matches'],result['disagreements']),(2,1,1,1))
        self.assertEqual(result['agreement_percentage'],50)
        self.assertEqual(result['confusion_matrix']['High']['Medium'],1)
        self.assertEqual(sum(sum(r.values()) for r in result['confusion_matrix'].values()),2)
        self.assertEqual(rows,original)
        self.assertIsNone(evaluation.summarize([])['agreement_percentage'])

    def test_real_pipeline_repeatability_integrity_and_explainability(self):
        # Byte-level protection: evaluation must not write into the user's DB.
        import app.database as database
        before=database.DATABASE.read_bytes()
        labels=evaluation.DATASET.read_bytes()
        methods=evaluation.methodology_digest()
        first=evaluation.evaluate()
        second=evaluation.evaluate()
        self.assertEqual(first,second)
        self.assertEqual(database.DATABASE.read_bytes(),before)
        self.assertEqual(evaluation.DATASET.read_bytes(),labels)
        self.assertEqual(evaluation.methodology_digest(),methods)
        self.assertEqual(len(first['results']),8)
        self.assertTrue(all(r['explainability']=='passed' for r in first['results']))
        self.assertEqual({r['evidence_state'] for r in first['results']},{'T1','T2','T3','T4','Inconclusive'})
        self.assertEqual(first['assessed']+first['unassessed'],8)
        for row in first['results']:
            if row['agreement']!='yes':
                self.assertTrue(row['explanation'])
        with closing(sqlite3.connect('file:'+str(database.DATABASE)+'?mode=ro',uri=True)) as db:
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_explainability_rejects_missing_recommendations(self):
        import test_phase9_end_to_end as harness
        fixture=harness.PhaseNineEndToEndTests('runTest')
        try:
            fixture.setUp()
            fixture.event('trace',0,'authentication_failed',['T1110'])
            harness._poll_once(100,0)
            _,incident=fixture.investigate_group()
            assessment=fixture.db.execute("SELECT * FROM risk_assessments WHERE assessment_stage='contextual'").fetchone()
            self.assertTrue(evaluation.trace_valid(fixture.db,incident,assessment))
            with fixture.db:
                fixture.db.execute('DELETE FROM contextual_recommendations')
            self.assertFalse(evaluation.trace_valid(fixture.db,incident,assessment))
        finally:
            if hasattr(fixture,'db'):
                fixture.tearDown()
            fixture.doCleanups()


if __name__=='__main__':
    unittest.main()
