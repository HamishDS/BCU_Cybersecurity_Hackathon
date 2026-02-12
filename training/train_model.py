import pandas as pd
import glob
import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, accuracy_score

# Configuration
DATA_DIR = 'data/'
MODEL_DIR = 'core/ai_models/'
MODEL_PATH = os.path.join(MODEL_DIR, 'threat_model.pkl')
ENCODERS_PATH = os.path.join(MODEL_DIR, 'encoders.pkl')

def load_data():
    """Loads and concatenates all labeled CSV files."""
    all_files = glob.glob(os.path.join(DATA_DIR, "*.labeled.csv"))
    df_list = []
    
    print(f"Found {len(all_files)} data files.")
    
    for filename in all_files:
        print(f"Loading {filename}...")
        # Zeek logs often use pipes as separators and # as comment chars (though these are CSVs)
        # Based on file check: pipe separated
        try:
            df = pd.read_csv(filename, sep='|', low_memory=False)
            df_list.append(df)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            
    if not df_list:
        raise ValueError("No data files found or loaded.")
        
    return pd.concat(df_list, ignore_index=True)

def preprocess_data(df):
    """Cleans and encodes data for training."""
    print("Preprocessing data...")
    
    # Target Selection: We train on 'detailed-label' to catch specific attacks
    # '-' usually means Benign in this dataset format
    df['detailed-label'] = df['detailed-label'].replace('-', 'Benign')
    
    # Feature Selection (Columns present in standard Zeek conn.log)
    features = ['proto', 'service', 'conn_state', 'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts']
    target = 'detailed-label'
    
    # Handle missing values in features
    # 'duration', 'orig_bytes', 'resp_bytes' are often '-' in Zeek logs for failed conns
    numeric_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts']
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
    # Fill string missing values
    df['proto'] = df['proto'].fillna('unknown')
    df['service'] = df['service'].replace('-', 'other').fillna('other')
    df['conn_state'] = df['conn_state'].fillna('OTH')

    X = df[features]
    y = df[target]
    
    # Encoding Categorical Features
    encoders = {}
    cat_features = ['proto', 'service', 'conn_state']
    
    for feature in cat_features:
        le = LabelEncoder()
        # Convert to string to handle mixed types, fill missing
        # Use .loc to ensure we modify the dataframe
        X.loc[:, feature] = X[feature].astype(str).fillna('missing')
        # Fit transform returns numpy array, assign it back
        X.loc[:, feature] = le.fit_transform(X[feature])
        encoders[feature] = le
        
    # Final check for NaNs and Infs
    if X.isnull().values.any():
        print("Warning: NaNs found in X. Filling with 0.")
        X = X.fillna(0)
    
    # Check for infinity
    import numpy as np
    if not np.isfinite(X.select_dtypes(include=[np.number])).all().all():
        print("Warning: Infinite values found in X. Replacing with 0.")
        X = X.replace([np.inf, -np.inf], 0)
        X = X.fillna(0)

    print("Final X dtypes:\n", X.dtypes)
    print("Final X head:\n", X.head())

    y = df[target].fillna('Benign') # Handle missing targets
    return X, y, encoders

def train():
    # 1. Load
    df = load_data()
    print(f"Total records: {len(df)}")
    
    # 2. Preprocess
    X, y, encoders = preprocess_data(df)
    
    # 3. Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # 4. Train
    print("Training Random Forest Model...")
    clf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    # 5. Evaluate
    em = clf.predict(X_test)
    print("Model Accuracy:", accuracy_score(y_test, em))
    print("\nClassification Report:\n", classification_report(y_test, em))
    
    # 6. Save
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
        
    print(f"Saving model to {MODEL_PATH}...")
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(encoders, ENCODERS_PATH)
    print("Done.")

if __name__ == "__main__":
    train()
