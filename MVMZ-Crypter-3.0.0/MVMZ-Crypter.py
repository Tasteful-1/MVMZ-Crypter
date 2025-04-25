from Resource.core.WebViewApp import WebViewApp

CURRENT_VERSION = "3.0.0"

def main():
    try:
        app = WebViewApp()
        app.run()
    except Exception as e:
        print(f"오류 발생: {str(e)}")
        input("계속하려면 아무 키나 누르세요...")

if __name__ == "__main__":
    main()