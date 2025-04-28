from fastapi import FastAPI 
from app.router import bot_router
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os 


load_dotenv()
groq_api_key = os.getenv('GOOGLE_API_KEY')



app =  FastAPI(
    title='Rafike ChatBot',
    description="Rafike ChatBot",
    version="0.0.1",
)


# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
    
)


@app.get('/health')
def health():
    return {'status': groq_api_key}


# //Add routers
app.include_router(bot_router.router)