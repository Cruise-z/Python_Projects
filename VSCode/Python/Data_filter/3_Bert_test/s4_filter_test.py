from transformers import DistilBertForSequenceClassification, AutoTokenizer
import torch

# 加载训练好的模型和分词器
model = DistilBertForSequenceClassification.from_pretrained("./results/checkpoint-15849")
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

# 示例句子
texts = [
    "Cybersecurity threats are evolving rapidly, requiring constant vigilance from organizations. As hackers become more sophisticated, it is essential for companies to stay updated on the latest security practices. Implementing a comprehensive security strategy that includes threat detection and incident response is crucial for protecting sensitive data.",  # 1
    "The latest update on network security protocols is crucial for safeguarding personal and business information. Organizations must regularly review and upgrade their systems to fend off potential attacks. Continuous training for employees on security awareness is also key in mitigating risks.",  # 1
    "Yoga and meditation are excellent practices for improving mental health and well-being. Many people find that incorporating mindfulness into their daily routines can lead to a more balanced life. These practices not only enhance focus but also promote relaxation and stress relief.",  # 0
    "Implementing multi-factor authentication can significantly reduce the risk of unauthorized access to sensitive accounts. By requiring multiple forms of verification, organizations can better protect their systems from cyber threats. This is a proactive step that all businesses should consider taking.",  # 1
    "Cooking is an art that requires both creativity and technique to create delicious meals. Whether experimenting with new recipes or perfecting classic dishes, the kitchen can be a place of innovation. Sharing meals with friends and family can also strengthen bonds and create lasting memories.",  # 0
    "Phishing attacks are increasingly sophisticated, often mimicking legitimate communications from trusted sources. It is vital for individuals to be aware of these tactics and to scrutinize messages before clicking on links or providing personal information. Awareness is the first line of defense against these threats.",  # 1
    "Traveling allows individuals to experience new cultures and broaden their perspectives. Exploring different countries can lead to personal growth and a better understanding of the world. Each journey offers unique opportunities to learn and connect with diverse communities.",  # 0
    "Regular software updates are essential to fix vulnerabilities and enhance security across systems. Organizations must prioritize these updates as part of their cybersecurity strategy. Ignoring updates can leave systems exposed to potential exploits and attacks.",  # 1
    "Gardening can be a therapeutic activity that connects people with nature. Tending to plants not only provides physical activity but also fosters a sense of accomplishment. Many find solace in the rhythm of planting and nurturing life in their gardens.",  # 0
    "Data breaches can lead to severe financial losses and damage to a company’s reputation. When sensitive information is compromised, the trust of customers can be irrevocably harmed. It is crucial for businesses to have a robust incident response plan in place to address such events swiftly.",  # 1
    "Reading fiction can stimulate imagination and improve empathy skills. Engaging with diverse characters and narratives allows readers to explore different perspectives. This immersive experience can enhance emotional intelligence and foster connections with others.",  # 0
    "Organizations must invest in employee training to recognize and respond to security threats effectively. Regular training sessions can empower staff to identify potential risks and take appropriate action. A well-informed workforce is a critical component of a strong cybersecurity posture.",  # 1
    "Hiking is a great way to explore the outdoors and stay physically active. It allows individuals to enjoy nature while reaping the physical benefits of exercise. Many people find that being in nature rejuvenates their spirits and promotes overall well-being.",  # 0
    "Using strong, unique passwords for each account is a fundamental practice in cybersecurity. Password managers can assist users in generating and storing complex passwords securely. This practice significantly reduces the risk of account takeovers and data breaches.",  # 1
    "Art and music have the power to evoke emotions and bring people together. Creative expression can be a powerful tool for communication and connection. Many find joy and inspiration in the arts, which can transcend language and cultural barriers.",  # 0
    "Ransomware attacks can cripple businesses, demanding payment to restore access to critical data. It is vital for organizations to have backup solutions in place and to educate employees about recognizing potential threats. Preparedness can mitigate the impact of such devastating attacks.",  # 1
    "Learning a new language can enhance cognitive skills and open up career opportunities. It challenges the brain and promotes cultural awareness. Many find that bilingualism offers personal and professional advantages in our increasingly globalized world.",  # 0
    "Network segmentation is a strategy to limit the spread of potential threats within an organization. By isolating critical systems, companies can better control access and reduce the risk of widespread damage. This proactive approach can significantly enhance overall security.",  # 1
    "Photography is a wonderful way to capture memories and express creativity. It allows individuals to share their perspectives and experiences with the world. Many find that photography fosters mindfulness and appreciation for the beauty in everyday life.",  # 0
    "Encryption is critical for safeguarding sensitive information from cybercriminals. By transforming data into unreadable formats, organizations can protect against unauthorized access. This fundamental practice is essential in maintaining the integrity and confidentiality of information.",  # 1
    "Volunteering in your community can foster connections and improve social cohesion. It provides an opportunity to give back while meeting new people and building relationships. Many find that community service enhances their sense of purpose and belonging."  # 0
]

standard_labels = [1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0]

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
# label_map = {0: 'negative', 1: 'positive'}
label_map = {0: 0, 1: 1}
predicted_labels = [label_map[label.item()] for label in predicted_labels]

print("Predicted categories:", predicted_labels)
print("Probabilities:", probabilities)
if(predicted_labels == standard_labels):
    print("match!!!")
else:
    print("miss match")
