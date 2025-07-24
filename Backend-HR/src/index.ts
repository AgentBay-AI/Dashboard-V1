import express from 'express';
import cors from 'cors';
import helmet from 'helmet';

const app = express();
const port = process.env.PORT || 8080;

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Basic route
app.get('/', (req, res) => {
  res.status(200).json({ message: 'HR Agent API is running' });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
}); 