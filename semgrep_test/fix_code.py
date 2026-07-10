import os
from dotenv import load_dotenv

from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_groq import ChatGroq

# -------------------------------
# Load API Key
# -------------------------------

load_dotenv()

# -------------------------------
# Read Extracted Code
# -------------------------------

with open("extracted_code.py", "r", encoding="utf-8") as f:
    code = f.read()

# -------------------------------
# Load LLM
# -------------------------------

llm = ChatGroq(
    model="llama-3.3-70b-versatile",
    temperature=0,
)

# -------------------------------
# Prompt
# -------------------------------

prompt = PromptTemplate.from_template(
"""
You are an expert Python security engineer.

Fix the security vulnerability in the following Python code.

Rules:
- Preserve the existing functionality.
- Do not rename functions.
- Return ONLY the corrected Python code.
- Do not include explanations.
- Do not use markdown.

Code:

{code}
"""
)

# -------------------------------
# LangChain Chain
# -------------------------------

chain = prompt | llm | StrOutputParser()

# -------------------------------
# Invoke
# -------------------------------

fixed_code = chain.invoke(
    {
        "code": code
    }
)

print("\n" + "="*70)
print("Corrected Code:\n")
print(fixed_code)
print("="*70)