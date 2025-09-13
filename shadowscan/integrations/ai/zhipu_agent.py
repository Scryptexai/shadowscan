import os
from dotenv import load_dotenv
from zhipuai import ZhipuAI

class ZhipuAgent:
    def __init__(self):
        # Load environment variables from .env file
        load_dotenv()
        
        api_key = os.getenv("ZHIPU_API_KEY")
        if not api_key:
            raise ValueError("ZHIPU_API_KEY not found in .env")
        self.client = ZhipuAI(api_key=api_key)

    def chat(self, prompt: str):
        try:
            response = self.client.chat.completions.create(
                model="glm-4.5",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error: {str(e)}"

    def code(self, instruction: str, context: str = ""):
        """Ask AI to generate or refactor code"""
        prompt = f"Refactor/generate Python module:\n{instruction}\n\nContext:\n{context}"
        return self.chat(prompt)
