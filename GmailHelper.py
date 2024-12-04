import os
import gpt4all

from dotenv import load_dotenv

load_dotenv()

MODEL_LOCATION = os.getenv("MODEL_LOCATION")

# Initialize the GPT4All model
model = gpt4all.GPT4All(MODEL_LOCATION)  # Replace with your model path

# Define the prompt
prompt = "Answer this prompt by saying 'Hello LLM'"
with model.chat_session():

    # Generate a response
    response = model.generate(prompt)

    # Print the response
    print(response)
