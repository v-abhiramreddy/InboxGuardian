import sys
import unittest
from unittest.mock import patch, MagicMock

# Mock google.genai so it doesn't crash on import
sys.modules['google'] = MagicMock()
sys.modules['google.genai'] = MagicMock()
sys.modules['google.genai.types'] = MagicMock()

from agents.llm_analysis_agent import analyze_email_with_llm

class TestFallbackLogic(unittest.TestCase):
    @patch('agents.llm_analysis_agent.genai.Client')
    def test_fallback_chain_success_on_third_try(self, mock_client_class):
        # We want the first 2 models to raise 429, and the 3rd to succeed.
        
        # Create a mock client instance
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # Mock the models.generate_content method
        def side_effect(*args, **kwargs):
            model = kwargs.get('model', '')
            if model in ['gemini-3.5-flash', 'gemini-3.1-pro']:
                raise Exception("429 RESOURCE_EXHAUSTED: Free tier quota exceeded")
            else:
                mock_resp = MagicMock()
                mock_resp.text = f"Success from {model}"
                return mock_resp
                
        mock_client.models.generate_content.side_effect = side_effect
        
        email_obj = {'body': 'test email'}
        scored = {'score': 50, 'category': 'scam'}
        
        result = analyze_email_with_llm(email_obj, scored, api_key="dummy")
        
        self.assertEqual(result, "Success from gemini-3.0-flash")
        print(f"\\n[RESULT] Final output was: {result}")

if __name__ == '__main__':
    unittest.main()
