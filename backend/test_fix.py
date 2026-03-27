from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_fix_endpoint():
    response = client.post(
        "/fix",
        json={
            "language": "javascript",
            "code_snippet": "element.innerHTML = userInput;",
            "issue_type": "XSS",
            "message": "Assigns raw HTML — any injected script will execute. Input is direct user input."
        }
    )
    print(f"Status: {response.status_code}")
    print("Fixed Code:")
    print("-------------------------------------------------")
    print(response.json().get("fixed_code"))
    print("-------------------------------------------------")

if __name__ == "__main__":
    test_fix_endpoint()
