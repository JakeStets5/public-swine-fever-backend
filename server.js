const express = require('express'); // Import the Express framework for building the server
const cors = require('cors'); // Import CORS middleware to handle cross-origin requests
const { BlobServiceClient } = require('@azure/storage-blob'); // Azure Blob Storage SDK for handling blob storage operations
const multer = require('multer'); // Multer for handling file uploads
require('dotenv').config(); // Loads environment variables from a .env file
const axios = require('axios'); // Import Axios for making HTTP requests
const app = express(); // Create an instance of the Express application
const bodyParser = require('body-parser'); // Body-parser to parse incoming request bodies
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing

// Variables to retrieve from Azure Key Vault
const { DefaultAzureCredential } = require("@azure/identity");
const { SecretClient } = require("@azure/keyvault-secrets");
const keyVaultUrl = "https://swine-fever-key-vault.vault.azure.net/";
const credential = new DefaultAzureCredential();
const client = new SecretClient(keyVaultUrl, credential);
let blobServiceClient; // Azure Blob Storage client
let PORT = 8080; // Port from environment variables
let azureUserContainerName; // Azure Blob Storage container name for user data
let azureImageContainerName; // Azure Blob Storage container name for images
let azureModelEndpoint; // Azure Machine Learning model endpoint
let azurePredictionKey; // Azure Machine Learning prediction key
let azureStorageConnectionString; // Azure Blob Storage connection string
let azureStorageAccountName; // Azure Blob Storage account name'
let googleMapsApiKey; // Google Maps API key
let mapboxApiKey; // Mapbox API key

// Middleware setup
app.use(cors()); // Use CORS middleware
app.options('*', cors()); // Enable preflight for all routes
app.use(express.json()); // Automatically parse incoming JSON payloads

// Middleware for parsing URL-encoded bodies and JSON requests
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Function to retrieve a single secret from Azure Key Vault
async function getSecret(secretName) {
  try {
    const retrievedSecret = await client.getSecret(secretName);
    return retrievedSecret.value; // Return the secret value
  } catch (error) {
    console.error(`Error retrieving secret ${secretName}:`, error);
  }
}

// Function to retrieve and initialize Azure Blob Storage client
async function initializeBlobServiceClient() {
  azureStorageConnectionString = await getSecret("AzureStorageConnectionString");
  return BlobServiceClient.fromConnectionString(azureStorageConnectionString);
}

// Function to retrieve account and container names from Azure Key Vault
async function initializeContainerNames() {
  azureStorageAccountName = await getSecret("AzureStorageAccountName");
  azureUserContainerName = await getSecret("AzureUserContainerName");
  azureImageContainerName = await getSecret("AzureImageContainerName");
  return { AzureUserContainerName: azureUserContainerName, AzureImageContainerName: azureImageContainerName, AzureStorageAccountName: azureStorageAccountName };
}

// Function to retrieve and initialize Azure Machine Learning model endpoint and prediction key
async function initializeAzureML() {
  azureModelEndpoint = await getSecret("AzureModelEndpoint");
  azurePredictionKey = await getSecret("AzurePredictionKey");
  return { AzureModelEndpoint: azureModelEndpoint, AzurePredictionKey: azurePredictionKey };
}

async function initializeApiKeys() {
  googleMapsApiKey = await getSecret("GoogleMapsApiKey");
  mapboxApiKey = await getSecret("MapboxApiKey");
  return { GoogleMapsApiKey: googleMapsApiKey, MapboxApiKey: mapboxApiKey };
}

// Multer configuration for handling file uploads
const upload = multer({ storage: multer.memoryStorage() }); // Files will be stored in memory for temporary use

// Sign-in endpoint
app.post('/api/signin', async (req, res) => {
  const { username, password } = req.body;

  // Check if all required fields are provided
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    blobServiceClient = await initializeBlobServiceClient(); // Initialize the Blob Service Client
    await initializeContainerNames(); // Initialize the container names

    const containerClient = blobServiceClient.getContainerClient(azureUserContainerName);
    let userExists = false;
    let storedPasswordHash = '';
    let organization = '';

    // Loop through the blobs in the useraccounts container to find the user
    for await (const blob of containerClient.listBlobsFlat()) {
      if (blob.name === `${username}.json`) {
        // Retrieve the user's blob content (JSON data)
        const blockBlobClient = containerClient.getBlockBlobClient(blob.name);
        const downloadBlockBlobResponse = await blockBlobClient.download(0);
        const downloadedData = await streamToString(downloadBlockBlobResponse.readableStreamBody);

        // Parse the blob content as JSON
        const userData = JSON.parse(downloadedData);

        // Retrieve the stored hashed password and organization
        storedPasswordHash = userData.password;
        organization = userData.organization;

        userExists = true;
        break; // Stop searching if the user is found
      }
    }

    if (!userExists) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Ensure storedPasswordHash is not undefined or null
    if (!storedPasswordHash) {
      console.error('No password hash found for the user.');
      return res.status(500).json({ error: 'No password hash found for the user.' });
    }

    // Compare the provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, storedPasswordHash);

    if (isMatch) {
      return res.status(200).json({ message: 'Sign-in successful!', username: username, organization: organization });
    } else {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
  } catch (error) {
    console.error('Error during sign-in:', error);
    return res.status(500).json({ error: 'Server error during sign-in.' });
  }
});

// Helper function to convert a readable stream to a string
async function streamToString(readableStream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    readableStream.on("data", (data) => {
      chunks.push(data.toString());
    });
    readableStream.on("end", () => {
      resolve(chunks.join(""));
    });
    readableStream.on("error", reject);
  });
}

// Sign-up endpoint
app.post('/api/signup', async (req, res) => {
  const { email, username, password, organization } = req.body;

  // Check if all required fields are provided
  if (!username || !password || !organization) {
    return res.status(400).json({ error: 'Organization, username, and password are required.' });
  }

  // Hash the password for security
  const hashedPassword = bcrypt.hashSync(password, 10);

  // Create user data as JSON
  const userData = {
    username,
    password: hashedPassword,
    organization,
    email
  };

  try {
    blobServiceClient = await initializeBlobServiceClient(); // Initialize the Blob Service Client
    await initializeContainerNames(); // Initialize the container names

    const containerClient = blobServiceClient.getContainerClient(azureUserContainerName);
    const blockBlobClient = containerClient.getBlockBlobClient(`${username}.json`);

    // Check if the user already exists by attempting to get the blob (JSON file)
    const exists = await blockBlobClient.exists();

    if (exists) {
      // If the user already exists, return an error
      return res.status(409).json({ error: 'User already exists' });
    }

    // If the user does not exist, proceed to upload the new user data
    await blockBlobClient.upload(JSON.stringify(userData), Buffer.byteLength(JSON.stringify(userData)));

    res.status(201).json({ message: 'User registered successfully', username: username, organization: organization });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

//endpoint to get neccessary keys
app.get('/api/keys', async (req, res) => {
  try {
    await initializeApiKeys();
    res.json({
      googleMapsApiKey: googleMapsApiKey.toString(),
      mapboxApiKey: mapboxApiKey.toString()
    });
  } catch (error) {
    console.error('Error fetching API keys:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

/**
 * API endpoint to fetch all positive test cases from the database.
 * Queries the 'model_results' table for entries where result = 1 (positive result).
 * Returns the results as an array of cases.
 */
app.get('/api/cases', async (req, res) => {

  try {
    blobServiceClient = await initializeBlobServiceClient(); // Initialize the Blob Service Client
    await initializeContainerNames(); // Initialize the container names

    const containerClient = blobServiceClient.getContainerClient(azureImageContainerName);
    const cases = [];

    // Iterate over each blob in the container
    for await (const blob of containerClient.listBlobsFlat()) {
      const blobClient = containerClient.getBlobClient(blob.name);
      const blobProperties = await blobClient.getProperties();

      // Check if the blob has a positive result
      if (blobProperties.metadata && blobProperties.metadata.result === 'positive') {
        // Construct a case object with relevant metadata
        cases.push({
          lat: blobProperties.metadata.lat || 0,
          lng: blobProperties.metadata.lng || 0,
          date: blobProperties.metadata.date,
          prob: blobProperties.metadata.probability,
          user: blobProperties.metadata.user,
          org: blobProperties.metadata.org,
        });
      }
    }

    // Send the cases as a JSON response
    if (cases.length === 0) {
      return res.status(404).json({ message: 'No cases found' });
    }
    res.json(cases);

  } catch (error) {
    console.error('Error fetching cases:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

/**
 * API endpoint to fetch the count of positive cases from the database.
 * Queries the database for results where result = 1 (positive).
 * Responds with the count of positive cases.
 */
app.get('/api/positive-count', async (req, res) => {

  try {
    blobServiceClient = await initializeBlobServiceClient(); // Initialize the Blob Service Client
    await initializeContainerNames(); // Initialize the container names

    const containerClient = blobServiceClient.getContainerClient(azureImageContainerName);
    let positiveCount = 0;

    // Iterate over each blob in the container
    for await (const blob of containerClient.listBlobsFlat()) {
      const blobClient = containerClient.getBlobClient(blob.name);
      const blobProperties = await blobClient.getProperties();

      // Check metadata for a positive result
      if (blobProperties.metadata && blobProperties.metadata.result === 'positive') {
        positiveCount++;
      }
    }

    // Respond with the positive count
    res.json({ positiveCount });
  } catch (error) {
    console.error('Error fetching positive case count:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

/**
 * API endpoint to fetch the count of negative cases.
 * Queries the database for results where result = 0 (negative).
 * Responds with the count of negative cases.
 */
app.get('/api/negative-count', async (req, res) => {

  try {
    blobServiceClient = await initializeBlobServiceClient(); // Initialize the Blob Service Client
    await initializeContainerNames(); // Initialize the container names

    const containerClient = blobServiceClient.getContainerClient(azureImageContainerName);
    let negativeCount = 0;

    // Iterate over each blob in the container
    for await (const blob of containerClient.listBlobsFlat()) {
      const blobClient = containerClient.getBlobClient(blob.name);
      const blobProperties = await blobClient.getProperties();

      // Check metadata for a positive result
      if (blobProperties.metadata && blobProperties.metadata.result === 'negative') {
        negativeCount++;
      }
    }

    // Respond with the positive count
    res.json({ negativeCount });
  } catch (error) {
    console.error('Error fetching negative case count:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

/**
 * API endpoint to retrieve all images stored in Azure Blob Storage.
 * Returns an array of image URLs.
 */
app.get('/retrieve-images', async (req, res) => {
  try {
      blobServiceClient = await initializeBlobServiceClient(); // Initialize the Blob Service Client
      await initializeContainerNames(); // Initialize the container names

      const containerClient = blobServiceClient.getContainerClient(azureImageContainerName);
      const images = [];

      // List all blobs in the container and push their URLs to the images array
      for await (const blob of containerClient.listBlobsFlat()) {
        const blockBlobClient = containerClient.getBlockBlobClient(blob.name); //blockBlobClient is the mediator between the app and the blob storage
        const imageUrl = `https://${azureStorageAccountName}.blob.core.windows.net/${azureImageContainerName}/${blob.name}`;

        // Get the blob properties, which include metadata
        const blobProperties = await blockBlobClient.getProperties();
        const metadata = blobProperties.metadata; // Retrieve the metadata from the blob properties
        images.push({ _id: blob.name, url: imageUrl, metadata: metadata || {} }); // Store the blob name and URL in the images array
      }

      res.json(images);
  } catch (error) {
      console.error('Error fetching images:', error);
      res.status(500).send('Error fetching images');
  }
});

/**
 * API endpoint for image upload and prediction.
 * Uploads an image to Azure Blob Storage and sends it to a machine learning model for prediction.
 */
app.post('/predict', upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  try {
    blobServiceClient = await initializeBlobServiceClient(); // Initialize the Blob Service Client
    await initializeContainerNames(); // Initialize the container names
    await initializeAzureML(); // Initialize the Azure Machine Learning model

    const apiKey = azurePredictionKey; // Retrieve the Azure Prediction key from environment variables
    
    // Send the image to your Azure Machine Learning model for prediction
    const modelResponse = await axios.post(
      azureModelEndpoint, // Send a POST request to the model endpoint
      req.file.buffer, // Send the image file buffer directly to the model API
      {
        headers: {
          'Prediction-Key': apiKey, // Add your Prediction-Key header
          'Content-Type': 'application/octet-stream', // Set content type to application/octet-stream
        },
      }
    );

    // Parse the prediction response
    if (modelResponse.data) {
      const predictions = modelResponse.data.predictions; // Extract the predictions from the API response
      let highestProbability = 0.0;
      let recognition = {
        tagName: "error",
        probability: 0.0,
      };

      // Loop through predictions to find the one with the highest probability
      for (let i = 0; i < predictions.length; i++) {
        const prediction = predictions[i];
        const probability = prediction.probability;

        // Keep track of the highest probability prediction
        if (probability > highestProbability) {
          highestProbability = probability;
          recognition = {
            tagName: prediction.tagName,
            probability: probability,
          };
        }
      }

      const lat = req.body.lat; // Latitude from the request body
      const lng = req.body.lng; // Longitude from the request body
      const user = req.body.user; // Username from the request body
      const org = req.body.org; // Organization name from the request body
      const prob = recognition.probability; // Probability value from the model prediction
      const currentDate = new Date(); // Get the current date
      const date = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}-${String(currentDate.getDate()).padStart(2, '0')}`; // Format the date

      // Upload the image to Azure Blob Storage
      const blobName = Date.now() + '-' + req.file.originalname; // Create a unique name for the uploaded file using the current timestamp
      const containerClient = blobServiceClient.getContainerClient(azureImageContainerName); // Get the container client for Azure Blob Storage
      const blockBlobClient = containerClient.getBlockBlobClient(blobName); // Get the block blob client to upload the file

      // Define metadata to attach to the blob
      const metadata = {
        lat: lat.toString() || 'unknown', 
        lng: lng.toString() || 'unknown', 
        result: recognition.tagName || 'unknown',
        probability: prob.toString() || 'unknown',
        user: user.toString() || 'anonymous',
        org: org || 'unknown',
        date: date.toString() || 'unknown'
      };

      // Upload the file to Azure Blob Storage with metadata
      await blockBlobClient.upload(req.file.buffer, req.file.size, {
        metadata: metadata
      });
      
      res.json(recognition); // Send the prediction result back to the client
    } else {
      res.status(500).json({ error: 'No predictions found in the response' });
    }
  } catch (error) {
    console.error('Error processing image:', error);
    res.status(500).json({ error: 'Error processing image' });
  }
});

// Start the server and listen on the specified port
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`); // Log server status
});