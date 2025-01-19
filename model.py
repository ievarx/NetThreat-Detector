import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# تحميل النموذج المدرب
def load_model():
    """
    تحميل النموذج المدرب من ملف pickle.
    :return: نموذج مدرب لتحليل البيانات.
    """
    try:
        with open('threat_classifier_model.pkl', 'rb') as file:
            model = pickle.load(file)
        return model
    except FileNotFoundError:
        raise Exception("Model file 'threat_classifier_model.pkl' not found.")
    except Exception as e:
        raise Exception(f"Error loading model: {str(e)}")

# تحليل الميزات باستخدام النموذج
def predict_attack(features):
    """
    تحليل الميزات المقدمة لتحديد إذا كانت تشير إلى هجوم.
    :param features: قائمة الميزات المستخرجة من الحزمة.
    :return: [0] أو [1] حيث 0 يعني حزمة طبيعية و1 يعني وجود هجوم.
    """
    try:
        # تحميل النموذج
        model = load_model()

        # تحويل الميزات إلى numpy array إذا لزم الأمر
        features = np.array(features).reshape(1, -1)

        # التنبؤ باستخدام النموذج
        prediction = model.predict(features)
        return prediction
    except Exception as e:
        raise Exception(f"Error during prediction: {str(e)}")
