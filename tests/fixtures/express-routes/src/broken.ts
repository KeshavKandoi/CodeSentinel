import express from 'express';

const brokenRouter = express.Router();
brokenRouter.get('/broken', (req, res) => {
  res.json({ oops: true
