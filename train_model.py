import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import numpy as np

# بيانات عشوائية (للاختبار فقط مو للاعتماد النهائي)
data = np.array([
    [50, 64, 6, 0],   # [Length, TTL, Protocol, Label]
    [70, 128, 17, 1],
    [60, 32, 6, 0],
    [90, 64, 6, 1],
    [40, 64, 6, 0],
    [80, 128, 17, 1],
])

# فصل الميزات (Features) والعلامات (Labels)
X = data[:, :-1]  # الميزات
y = data[:, -1]   # العلامات

# تقسيم البيانات إلى تدريب واختبار
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# تدريب النموذج
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# اختبار النموذج
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model accuracy: {accuracy * 100:.2f}%")

# حفظ النموذج المدرب
with open('threat_classifier_model.pkl', 'wb') as file:
    pickle.dump(model, file)
print("Model saved as 'threat_classifier_model.pkl'.")
