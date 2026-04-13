# PhishEagle

![Repository](https://img.shields.io/badge/repo-PhishEagle-blue) ![Python](https://img.shields.io/badge/python-%3E%3D3.8-blue) ![Status](https://img.shields.io/badge/status-active-green)

PhishEagle is an ML-based phishing detection system that uses a Random Forest classifier to identify phishing websites and provide warnings via a Chrome extension.

---

## 🔎 Project Overview
- Goal: Accurately detect phishing websites using machine learning and integrate detection into a Chrome extension for real-time warnings.  
- Model: Random Forest Classifier  
- Reported accuracy: 99.40%  
- Published: [International Journal of Intelligent Systems and Applications in Engineering](https://ijisae.org/index.php/IJISAE/article/view/7071)

---

## 🧰 Technologies & Libraries
- Python (scikit-learn, pandas, numpy)
- Jupyter Notebooks (analysis & experiments)
- Chrome Extension (HTML / JS / CSS)

---

## 🛠 Training & Evaluation
1. Preprocessing: Feature extraction from URLs, HTML content, WHOIS information, and SSL certificates.  
2. Train/Test Split: Data was divided into 70% training and 30% testing sets with cross-validation.  
3. Classifier: RandomForestClassifier (tuned with grid search).  
4. Metrics Reported: Accuracy, precision, recall, F1 score, and confusion matrix.  

---

## 📚 Dataset
- Dataset Name: Phishing Websites Dataset  
- Source / Link: [Mendeley Data](https://data.mendeley.com/datasets/72ptz43s9v/1)  
- Publisher / Contributor: Grega Vrbančič  
- License: CC BY 4.0  
- Description:  
  This dataset contains features extracted from URLs, HTML content, WHOIS information, and SSL certificates to classify websites as phishing or legitimate.  
  It includes two variants:  
  1. Full dataset (`dataset_full.csv`): 88,647 entries (58,000 legitimate, 30,647 phishing)  
  2. Small dataset (`dataset_small.csv`): 58,645 entries (27,998 legitimate, 30,647 phishing)  
