import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report


df = pd.read_csv("Phishing_Legitimate_full.csv")

print(f"✅ Dataset loaded: {len(df)} URLs")
print(f"📊 Phishing: {len(df[df['CLASS_LABEL']==1])} | Legitimate: {len(df[df['CLASS_LABEL']==0])}")

X = df.drop(columns=['id', 'CLASS_LABEL'])
y = df['CLASS_LABEL']


X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)


scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)


model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_scaled, y_train)


y_pred = model.predict(X_test_scaled)
print(f"\n✅ Model trained successfully")
print(f"📊 Accuracy: {round(accuracy_score(y_test, y_pred) * 100, 2)}%")
print(f"\n📋 Report:\n{classification_report(y_test, y_pred)}")


pickle.dump(model, open('link_model.pkl', 'wb'))
pickle.dump(scaler, open('link_scaler.pkl', 'wb'))
pickle.dump(list(X.columns), open('link_features.pkl', 'wb'))

print("💾 link_model.pkl, link_scaler.pkl, link_features.pkl saved")
