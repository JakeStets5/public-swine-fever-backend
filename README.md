# Swine Fever Website Backend

## Overview
This backend serves as the API for the Swine Fever Website, which is built using React. It connects to an Azure database for storing images and an SQLite database for holding test results. The backend is responsible for handling requests from the frontend and processing data from the machine learning model.

## Technologies Used
- **Programming Language**: JavaScript
- **Framework**: [Express.js](https://expressjs.com/)
- **Database**: 
  - Azure Blob Storage (for images)
  - SQLite (single table for results)
- **Machine Learning Model**: Azure custom vision model 

## Setup Instructions
To run the backend locally, follow these steps:

1. **Clone the Repository**.
2. **Install Dependencies** using `npm install`.
3. **Configure Environment Variables**: Create a `.env` file in the root directory and add necessary environment variables (like Azure credentials, etc.).
4. **Run the Server** using `npm start`.

## API Documentation
### Endpoints
- **GET /api/cases**
  - Retrieves all results from the SQLite database.
  
- **POST /predict**
  - Accesses the machine learning model to analyze a test.
  - Request Body:
    ```json
    {
      "result": "1(positive)/0(negative)",
      "lat": "user latitiude",
      "lng": "user longitude",
      "user": "username",
      "org": "user organization",
      "prob": "the confidence of the model",
      "date": "submission date"
    }
    ```

## Contributing
Contributions will likely not be viewed. As this is part of a deployed website, any changes made will not be able to be tested. See the local backend repository for testing [here](https://github.com/JakeStets5/swine-fever-backend-local) 
