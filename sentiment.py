from textblob import TextBlob
from textblob.classifiers import NaiveBayesClassifier
import os
import csv

class SentimentAnalyzer:
    def __init__(self, data_file='feedback_dataset.csv'):
        self.cl = None
        self.data_file = data_file
        self._train_model()

    def _train_model(self):
        """Trains a Naive Bayes Classifier on the dataset."""
        if not os.path.exists(self.data_file):
            print("Warning: Dataset not found. Using default TextBlob sentiment.")
            return

        with open(self.data_file, 'r') as fp:
            reader = csv.reader(fp, delimiter=',')
            next(reader) # Skip header
            train_data = [(row[0], row[1]) for row in reader]
            
        print("Training sentiment model...")
        self.cl = NaiveBayesClassifier(train_data)
        print("Model trained.")

    def analyze(self, text):
        """Returns 'Good', 'Bad', or 'Neutral' based on text."""
        if not text:
            return "Neutral"

        # Use the classifier if available
        if self.cl:
            prob_dist = self.cl.prob_classify(text)
            label = prob_dist.max()
            
            # Map labels to UI format
            if label == 'pos': return "Good"
            if label == 'neg': return "Bad"
            return "Neutral"
        
        # If model failed to load, return Neutral (don't use English TextBlob)
        return "Neutral"

# Singleton instance
analyzer = SentimentAnalyzer()
