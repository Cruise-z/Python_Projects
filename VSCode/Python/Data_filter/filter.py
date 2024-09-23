from transformers import DistilBertForSequenceClassification, AutoTokenizer
import torch

# 加载训练好的模型和分词器
model = DistilBertForSequenceClassification.from_pretrained("./results/checkpoint-15849")
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

# 示例句子
# 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0
# 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0
texts = [
    "Cybersecurity is crucial for protecting data.", 
    "Traveling allows individuals to experience different cultures, explore new landscapes, and gain fresh perspectives on the world.",
    "As the Internet of Things (IoT) continues to expand, securing interconnected devices has become a pressing concern. Hackers can exploit vulnerabilities in smart homes, cars, and wearable devices, compromising personal data and privacy. Strong encryption, regular software updates, and secure authentication methods are critical to protecting these devices from cyberattacks.",
    "Hiking in nature allows individuals to disconnect from their daily routines and reconnect with the natural world. Whether trekking through forests or scaling mountains, hiking offers a peaceful escape and promotes physical fitness. The beauty of nature and the serenity of outdoor exploration provide a much-needed mental reset.",
    "Cloud computing has transformed the way businesses store and access data, but it also introduces new cybersecurity challenges. Companies must ensure that cloud platforms are secure, utilizing multi-factor authentication, data encryption, and secure access control. As more organizations adopt cloud services, maintaining data security in the cloud becomes increasingly vital.",
    "Music is a universal language that transcends cultural barriers, bringing people together through shared melodies and rhythms. From classical symphonies to modern pop, music has the power to evoke emotions and create lasting memories. Whether as a performer or a listener, music enriches life in countless ways.",
    "Deep learning is a subset of machine learning that mimics the workings of the human brain in processing data and recognizing patterns. It has numerous applications in cybersecurity, such as detecting malware, identifying phishing attempts, and analyzing large datasets for unusual activity that may indicate a cyber threat.",
    "Painting is a form of artistic expression that allows individuals to communicate their emotions and ideas visually. Whether using watercolors, oils, or acrylics, painting provides a creative outlet and a way to explore different techniques and styles. The process of creating art can be both therapeutic and intellectually stimulating.",
    "Biometric authentication methods, such as fingerprint scanning and facial recognition, are becoming more prevalent in securing devices and systems. While convenient, these methods also raise privacy concerns and create new targets for cybercriminals. Ensuring the security of biometric data is crucial to preventing unauthorized access and identity theft.",
    "Running is one of the simplest forms of exercise that requires little more than a good pair of shoes and some open space. It offers numerous physical and mental health benefits, including improved cardiovascular fitness, stress relief, and enhanced mood. Many find running to be an excellent way to clear their minds and stay active.",
    "The rise of 5G networks promises faster internet speeds and more reliable connections, but it also introduces new security challenges. With more devices connected to these high-speed networks, securing the infrastructure against cyber threats becomes paramount. Network providers must implement robust security protocols to protect against data breaches and unauthorized access.",
    "Photography is a way to capture moments and preserve memories, allowing people to express themselves creatively. Whether through portrait, landscape, or street photography, the art form provides a unique perspective on the world and helps people connect with their surroundings in a meaningful way.",
    "For many years, UNESCO and China have collaborated closely in the field of world heritage. Among the 35 Chinese properties on the World Heritage List, there are 25 cultural, 6 natural and 4 mixed sites. China is working with the countries of Central Asia (Kazakhstan, Kyrgyzstan, Tajikistan, Turkmenistan and Uzbekistan) on a Serial World Heritage Nomination of the Silk Roads. Like the country itself, China’s intangible cultural heritage is of extremely vast. The Kun Qu Opera was proclaimed a Masterpiece of the Oral and Intangible Heritage of Humanity in 2001, and the Guqin and its Music in 2003. The Uyghur Muqam of Xinjiang and the Urtiin Duu – Traditional Folk Long Song (the latter was submitted together with Mongolia) were awarded this distinction in 2005. A number of field projects have been devoted to endangered languages. With regard to cultural diversity, the cultural approach to the prevention and treatment of HIV and AIDS is being studied by officials. Crafts that make it possible to maintain traditional techniques - frequently the preserve of women - as well as community economic development are being promoted in some regions. China also collaborates with UNESCO in the area of dialogue through the programme on Intercultural Dialogue in Central Asia. In the framework of this programme, China is a member of the International Institute for Central Asian Studies, which was created to encourage intellectual cooperation among the Member States of the region.",
]

# 预处理输入数据
inputs = tokenizer(texts, padding=True, truncation=True, return_tensors="pt")

# 进行预测
model.eval()
with torch.no_grad():
    outputs = model(**inputs)

# 获取 logits 和预测结果
logits = outputs.logits
probabilities = torch.nn.functional.softmax(logits, dim=-1)
predicted_labels = torch.argmax(probabilities, dim=-1)

# 标签到类别的映射
label_map = {0: 'negative', 1: 'positive'}
predicted_labels = [label_map[label.item()] for label in predicted_labels]

print("Predicted categories:", predicted_labels)
print("Probabilities:", probabilities)
