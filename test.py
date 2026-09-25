from google import genai

client = genai.Client(api_key="YOUR_API_KEY_HERE")


for model in client.models.list():
    print(model.name)