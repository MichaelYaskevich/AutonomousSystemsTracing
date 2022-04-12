import unittest

from task import run


class TraceTest(unittest.TestCase):
    def test_trace_with_wrong_domain_name(self):
        result = []
        run("wrong_domain_name", result.append)
        self.assertTrue(len(result) == 1)
        self.assertEqual(result[0], "Не удается разрешить системное имя узла wrong_domain_name.")

    def test_trace_with_wrong_ip(self):
        result = []
        run("2000.255.255.255", result.append)
        self.assertTrue(len(result) == 1)
        self.assertEqual(result[0], "Не удается разрешить системное имя узла 2000.255.255.255.")

    def test_trace_with_correct_domain_name(self):
        result = []
        run("vk.com", result.append)
        self.assertTrue(len(result) > 1)

    def test_trace_with_correct_ip(self):
        result = []
        run("5.255.255.77", result.append)
        self.assertTrue(len(result) > 1)
