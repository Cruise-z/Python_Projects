import re

def contains_keywords(text, keywords):
    """
    检查文本中是否包含任何简化和扩展关键词，并返回第一个匹配的关键词。
    :param text: 待检查的文本
    :param keywords: 网络安全相关的关键词集合
    :return: 匹配到的第一个关键词，如果没有匹配到则返回None.
    """
    # 对每个关键词进行遍历，查找第一个匹配项
    for keyword in keywords:
        if re.search(re.escape(keyword), text, re.IGNORECASE):
            return keyword  # 返回匹配到的第一个关键词
    return None  # 如果没有匹配到任何关键词，则返回None

# 示例使用
keywords = ["firewall", "VPN", "IDS"]  # 关键词列表示例
text = "This report discusses various aspects of a VPN configuration."
found_keyword = contains_keywords(text, keywords)

if found_keyword:
    print(f"Found keyword: {found_keyword}")
else:
    print("No keyword found.")


'''
Making the Case for Action\nThis fact sheet(pdf) and slide deck provide essential state-specific information that addresses the economic imperative, the equity imperative, and the expectations imperative of the college- and career-ready agenda. These resources can be used on their own or serve as the foundation for a personalized presentation or fact sheet(word), which can be customized with state-specific details and examples. The PowerPoint, in particular, was developed with various users in mind and offers a wide range of case-making data that can be drawn from to support your own advocacy efforts.\nAdvancing the Agenda\nAs states continue their efforts to promote college and career readiness, Achieve regularly surveys the states to identify their progress in adopting critical college- and career-ready policies. Below is a summary of Idaho's progress to date:\nSee Closing the Expectations Gap for more information\nState accountability systems focus the efforts of teachers, students, parents, administrators and policymakers to ensure that students and schools meet the established goals, including the goal of ensuring all students graduate ready for college and careers. Idaho has yet to begin to use any of the key college- and career-ready indicators in their accountability system.\n|Annual School-level Public Reporting||Statewide Performance Goals||School-level Incentives||Accountability Formula|\n|Earning a college- and career-ready diploma|\n|Scoring college-ready on a high school assessment|\n|Earning college credit while in high school|\n|Requiring remedial courses in college|\nFor an explanation of the indicators, their uses and Achieve’s minimum criteria for college- and career-ready accountability, see here.
Question: How is bipolar disorder different from unipolar depression or 'regular' depression?\nAnswer: Both bipolar disorder and major depression are typically associated with depressive episodes. So both illnesses are accompanied by depressions. The difference is that in bipolar disorder people also have periods of elevation -- or severe irritability. We call these manic or hypomanic episodes.
Nuclear Energy in France\nNuclear energy is the cornerstone of french energy policy. In the ‘70s France chose to develop nuclear as its base load electricity source as a response to the oil crisis and assure its energy independence.\nNuclear Electricity Production: France currently counts 58 commercial nuclear reactors in operation responsible for producing 80% of French domestic electricity. As a comparison, the 104 US reactors produces 20% of US electricity.Despite scarce natural resources, France has reached an energy independence of 50% thanks to its strategic choice for nuclear energy.\nEnvironment: As well as providing safe and reliable energy, nuclear helps to reduce French greenhouse gas emissions by avoiding the release of 31 billions tones of carbon dioxide (contrary to coal or gas generation) and making France the less carbon emitting country within the OECD. As a leader in nuclear energy, France has developed clean technology for radioactive waste disposal. Reprocessing currently allows France to recover valuable elements from spent fuels and permit a significant reduction of high level waste and lead to safer and optimized containment, for final radioactive waste disposition. French nuclear power plants produces only 10 g/year/inhabitant of highly radioactive waste.\nInternational Cooperation and research: France is one of the forerunner in nuclear research and participates in numerous international cooperation programs alongside the United States such as the development of the next generation of nuclear power plants (Gen IV) and the International Thermonuclear Experimental Reactor (ITER) that will be built in Cadarache, South of France.\nThe French Atomic Energy Commission (CEA)\nThe French Atomic Energy Commission is a public body established in October 1945 by General de Gaulle. It constitutes a power of expertise and proposition for the authorities. A leader in research, development and innovation, the CEA is involved in three main fields:\nIt develops and acquires the technological building blocks necessary to the development of the nuclear reactors of the future (Contribution to Generation IV and GNEP research),\nIt contributes to reducing greenhouse gas emission with its research on hydrogen, fuel cells, biomass, energy storage…,\nIt supports the nuclear utilities in France by optimizing the nuclear power plants of the French nuclear fleet and by optimizing the fuel cycle,\nIt offers safe and economically viable technical solutions for managing nuclear waste,\nIt conducts fundamental research in climate and environmental sciences, high energy physics, astrophysics, fusion, nanosciences…\nInformation and Health technologies:\nIt tackles micro and nano-technologies for telecommunication and nuclear medicine for radiotherapy and medical imaging,\nIt researches programs on biotechnology, molecular labelling, biomolecular engineering and structural biology,\nIt shares its knowledge and know-how through education and training through the National Institute for Nuclear Sciences and Technologies (INSTN),\nIt manages over 300 priority patents and is active in the creation of clusters.\nDefense and National Security:\nIt conceives, builds, maintains then dismantles the nuclear warhead of the French deterrence force,\nIt helps to fight against nuclear, biological and chemical weapons (NRBC program).\nThe missions of the CEA are similar to the Department of Energy in the United States. The CEA has a network of counselor or representatives in French Embassies around the world (see joint map).\nThe French Nuclear Safety Authority (ASN)\nCreated in 2006, from the former DSIN (Directorate for the Safety of Nuclear Facilities), the French Nuclear Safety Authority is an independent administrative authority which is tasked with regulating nuclear safety and radiation protection in order to protect workers, patients, the public and the environment from the risks involved in nuclear activities. It also contributes to informing the public. Like the Nuclear Regulatory Commission in the United States, it carries out inspections and may pronounce sanctions, up to and including suspension of operation of an installation.\nFrench Institute for Radioprotection and Nuclear Safety (IRSN)\nCreated in 2001 by merging the Protection and Nuclear Safety Institute (IPSN) and the Ionizing radiations Protection Office (OPRI), the Institute for Radioprotection and Nuclear Safety is a public establishment of an industrial and commercial nature placed under the joint authority of the Ministries of the Environment, Health, Industry, Research and Defense. It is the expert in safety research and specialized assessments into nuclear and radiological risk serving public authorities whose work is complementary to the ASN.\nIts scope of activities includes:\nenvironment and response,\nhuman radiological protection,\nresearch on the prevention of major accidents,\npower reactor safety,\nfuel cycle facility safety,\nresearch installation safety,\nwaste management safety;\nnuclear defense expertise.\nNational radioactive Waste Management Agency (ANDRA)\nCreated in 1991, the French National Agency for Radioactive Waste Management is a public industrial and commercial organization that operates independently of waste producers. It is responsible for the long-term management of radioactive waste produced in France under the supervision of the French Ministries for Energy, Research and the Environment. It can be compared to a certain extent to the Office for Nuclear Waste of the Department of Energy in the United States.\nAndra also pursues industrial, research, and information activities as it designs and implements disposal solutions suited to each category of radioactive waste:\nthe collection, conditioning, disposal of radioactive waste from small producers (hospitals, research centers, industry),\nspecification of waste packages for disposal,\ndisposal in suited sites,\nmonitoring of closed disposal facilities,\nresearch programs for long-lived and high level activity waste, especially through the operation of an underground research laboratory in a deep clay formation…\nGeneral Directorate for Energy and Climate (DGEC)\nThe General Directorate for Energy and Climate represents the government and is part of the Office of the Department for Ecology and Sustainable Development. It defines the French nuclear policy. The DGEC takes care of the energy supply, the security of supply, oil refining and logistics, nuclear industry, and coal and mines.\nConsequently, its activities include:\nthe design and implement energy and raw material supply policy,\nto ensure opening of electricity and gas markets,\ntrack key energy and raw material sectors,\nto oversee enterprises and public institutions in energy sector,\nto ensure compliance with rules and regulations governing energy sector,\nto participate in European and international energy projects and working groups,\nto provide economic, environmental, and fiscal expertise on energy matters.\nThe Rise of Nuclear Power Generation in France.
|Elevation||4,095 m (13,435 ft)|\n|Prominence||4,095 m (13,435 ft)\n|Listing||Country high point\nJohn Whitehead (highest peak)\nMount Kinabalu (Malay: Gunung Kinabalu) is a prominent mountain on the island of Borneo in Southeast Asia. It is located in the East Malaysian state of Sabah and is protected as Kinabalu National Park, a World Heritage Site. Kinabalu is the highest peak in Borneo's Crocker Range and is the highest mountain in the Malay Archipelago. Mount Kinabalu is also the 20th most prominent mountain in the world by topographic prominence.\nIn 1997, a re-survey using satellite technology established its summit (known as Low's Peak) height at 4,095 metres (13,435 ft) above sea level, which is some 6 metres (20 ft) less than the previously thought and hitherto published figure of 4,101 metres (13,455 ft).\nMount Kinabalu includes the Kinabalu montane alpine meadows ecoregion in the montane grasslands and shrublands biome. The mountain and its surroundings are among the most important biological sites in the world, with between 5000 and 6000 species of plants, 326 species of birds, and more than 100 mammalian species identified. Among this rich collection of wildlife are famous species such as the gigantic Rafflesia plants and the orangutan. Mount Kinabalu has been accorded UNESCO World Heritage status.\nLow's Peak can be climbed quite easily by a person in good physical condition and there is no need for mountaineering equipment at any point on the main route. Other peaks along the massif, however, require rock climbing skills.\nSignificantly, Mount Kinabalu along with other upland areas of the Crocker Range is well-known worldwide for its tremendous botanical and biological species biodiversity with plants of Himalayan, Australasian, and Indomalayan origin. A recent botanical survey of the mountain estimated a staggering 5,000 to 6,000 plant species (excluding mosses and liverworts but including ferns), which is more than all of Europe and North America (excluding tropical regions of Mexico) combined. It is therefore one of the world's most important biological sites.\nThe flora covers the mountain in zones of different types of habitat as one climbs up, beginning with a lowland belt of fig trees and insectivorous pitcher plants. Then between 2,600 to 3,200 m (8,530 to 10,499 ft) is a layer of short trees such the conifer Dacrydium gibbsiae and dwarf shrubs, mosses, lichens, liverworts, and ferns. Finally many of the world's richest variety of orchids are found on the high rockier slopes.\nThese plants have high levels of endemism (i.e. species which are found only within Kinabalu Park and are not found anywhere else in the world). The orchids are the best-known example with over 800 species including some of the highly-valued Paphiopedilum slipper orchids, but there are also over 600 species of ferns (more than the whole of Africa's 500 species) of which 50 are found nowhere else, and the richest collection in the world for the Nepenthes pitcher plants (five of the thirteen are found nowhere else on earth) which reach spectacular proportions (the largest-pitchered in the world being the endemic Nepenthes rajah). The parasitic Rafflesia plant, which has the largest single flower in the world, is also found in Kinabalu (particularly Rafflesia keithii whose flower grows to 94 centimetres (37 in) in diameter), though it should be noted that blooms of the flower are rare and difficult to find. Meanwhile another Rafflesia species, Rafflesia tengku-adlinii, can be found on the neighbouring Mount Trus Madi and the nearby Maliau Basin.\nIts incredible biodiversity in plant life is due to a combination of several unique factors: its setting in one of the richest plant regions of the world (the tropical biogeographical region known as western Malesia which comprises the island of Sumatra, the Malay Peninsula, and the island of Borneo), the fact that the mountain covers a wide climatic range from near sea level to freezing ground conditions near the summit, the jagged terrain and diversity of rocks and soils, the high levels of rainfall (averaging about 2,700 millimetres (110 in) a year at park HQ), and the climatic instability caused by periods of glaciation and catastrophic droughts which result in evolution and speciation. This diversity is greatest in the lowland regions (consisting of lowland dipterocarp forests, so called because the tree family Dipterocarpaceae are dominant). However, most of Kinabalu's endemic species are found in the mountain forests, particularly on ultramafic soils (i.e. soils which are low in phosphates and high in iron and metals poisonous to many plants; this high toxic content gave rise to the development of distinctive plant species found nowhere else).\nThe variety of plant life is also habitat for a great variety of birds and animals. There are some 326 species of birds in Kinabalu Park, including the spectacular Rhinoceros Hornbill, Mountain Serpent-eagle, Dulit Frogmouth, Eyebrowed Jungle Flycatcher, and Bare-headed Laughingthrush. Twenty-four birds are mainly found on the mountain and one, the Bornean Spiderhunter, is a pure endemic. The mountain is home to some 100 mammalian species mostly living high in the trees, including one of the four great apes, the orangutan (though sightings of these are uncommon; estimates of its numbers in the park range from 25 to 120). Other mammals include three kinds of deer, the Malayan Weasel (Mustela nudipes), Oriental Small-clawed Otter (Aonyx cinerea), and Leopard Cat (Felis bengalensis). Endemic mammals include the Black Shrew (Suncus ater) and Bornean Ferret-badger (Melogale everetti).\nThreats and preservation \nThe steep mountainsides with poor soil are not suitable for farming or for the timber industry so the habitats and animal life of Kinabalu remain largely intact, with about a third of the original habitat now degraded. Kinabalu Park was established in 1964 and the nearby mountains were protected as the Crocker Range National Park in 1984. However even national park status does not guarantee full protection, as logging permits were granted on Trus Madi in 1984.\nMount Kinabalu is essentially a massive pluton formed from granodiorite which is intrusive into sedimentary and ultrabasic rocks, and forms the central part, or core, of the Kinabalu massif. The granodiorite is intrusive into strongly folded strata, probably of Eocene to Miocene age, and associated ultrabasic and basic igneous rocks. It was pushed up from the earth's crust as molten rock millions of years ago. In geological terms, it is a very young mountain as the granodiorite cooled and hardened only about 10 million years ago. The present landform is considered to be a mid-Pliocene peneplain, arched and deeply dissected, through which the Kinabalu granodiorite body has risen in isostatic adjustment. It is still pushing up at the rate of 5 mm per annum. During the Pleistocene Epoch of about 100,000 years ago, the massive mountain was covered by huge sheets of ice and glaciers which flowed down its slopes, scouring its surface in the process and creating the 1,800-metre (5,900 ft) deep Low's Gully (named after Hugh Low) on its north side. Its granite composition and the glacial formative processes are readily apparent when viewing its craggy rocky peaks.\nBritish colonial administrator Hugh Low made the first recorded ascent of Mount Kinabalu's summit plateau in March 1851. Low did not scale the mountain's highest peak, however, considering it \"inaccessible to any but winged animals\". In April and July 1858, Low was accompanied on two further ascents by Spenser St. John, the British Consul in Brunei. The highest point of Mount Kinabalu was finally reached in 1888 by zoologist John Whitehead. British botanist Lilian Gibbs became the first woman and the first botanist to summit Mount Kinabalu in February 1910.\nBotanist E. J. H. Corner led two important expeditions of the Royal Society of Great Britain to the mountain in 1961 and 1964. Kinabalu National Park was established in 1964. The park was designated a natural World Heritage Site in 2000.\nClimbing route \nClimbers must be accompanied by accredited guides at all times due to national park regulations. There are two main starting points for the climb: the Timpohon Gate (located 5.5 km from Kinabalu Park Headquarters, at an altitude of 1,866 metres (6,122 ft)), and the Mesilau Nature Resort. The latter starting point is slightly higher in elevation, but crosses a ridge, adding about two kilometres to the ascent and making the total elevation gain slightly higher. The two trails meet about two kilometres before Laban Rata.\nAccommodation is available inside the park or outside near the headquarters. Sabah Parks has privatised Mount Kinabalu activities to an organisation called Sutera Sanctuary Lodges (also known as Sutera Harbour). The mountain may be climbed on a single day trip, or hikers may (usually) stay one night at Laban Rata Resthouse at 3,270 metres (10,730 ft) to complete the climb in 2 days, finishing the ascent and descending on the second day. The majority of climbers begin the ascent on day one of a two-day hike from Timpohon gate at 1,866 metres (6,122 ft), reaching this location either by minibus or by walking, and then walk to Laban Rata. Most people accomplish this part of the climb in 3 to 6 hours. Since there are no roads, the supplies for the Laban Rata Resthouse are carried by porters, who bring up to 35 kilograms of supplies on their backs. Hot food and beverages are available at Laban Rata. Most rooms have no hot water in the bathrooms and whilst the dining area is heated, most rooms are not. The last 2 kilometres (6,600 ft), from the Laban Rata Resthouse at 3,270 metres (10,730 ft) to Low's Peak (summit) at 4,095.2 metres (13,436 ft), takes between 2 and 4 hours. The last part of the climb is on naked granite rock.\nGiven the high altitude, some people may suffer from altitude sickness and should return immediately to the bottom of the mountain, as breathing and any further movement becomes increasingly difficult.\nLow's gully \nLow's Gully (named after Hugh Low) is a 1,800-metre (5,900 ft) deep gorge on the north side of Mount Kinabalu, one of the least explored and most inhospitable places on earth. In 1994 two British Army officers were severely criticised after having led a party of 10 adventurers that required extensive rescue efforts from both the RAF and the Malaysian army. Five members of the party were trapped for 16 days and did not eat for five days before being rescued. The breakaway party of five successfully completed the world's first descent of the gully in three days.\nThere are two stories that led to the main beliefs in the origin of the mountain's name.\nThe first derivation of the word Kinabalu is extracted from the short form for the Kadazan Dusun word 'Aki Nabalu', meaning \"the revered place of the dead\".\nThe second source states that the name \"Kinabalu\" actually means \"Cina Balu\" (which would fully mean \"A Chinese Widow\"). Due to the lingual influence among the Kadazan Dusun of Sabah, the pronunciation for the word \"cina\" (chee-na) was changed to \"Kina\" (kee-na).\nIt was told that a Chinese prince, was cast away to Borneo when his ship sank in the middle of the South China Sea. He was subsequently rescued by the natives from a nearby village. As he recovered, he was slowly accepted as one of the people of the village. Eventually, he fell in love with a local woman, and married her. Years went by, and he started to feel homesick. So he asked permission from his newly-found family to go back to China to visit his parents (the Emperor and Empress of China). To his wife, he promised that as soon as he was done with his family duties in China, he would come back to Borneo to take her and their children back to China.\nWhen he made his return to China, he was given a grand welcome by his family. However, to his dismay, his parents disagreed with him about taking his Bornean wife back to China. Worse, they told him that he was already betrothed to a princess of a neighbouring kingdom. Having no choice (due to high respect towards his parents), he obeyed with a heavy heart.\nMeanwhile, back in Borneo, his wife grew more and more anxious. Eventually, she decided that she will wait for her husband's ship. However, since the village was situated far away from the coast, she couldn't afford to come to the shore and wait for him daily. Instead she decided to climb to the top of the highest mountain near her village, so that she could have a better view of the ships sailing in the South China Sea. Thus, she was then seen climbing up the mountain at every sunrise, returning only at night to attend to her growing children.\nEventually her efforts took their toll. She fell ill, and died at the top of the cold mountain while waiting for her husband. The spirit of the mountain, having observed her for years, was extremely touched by her loyalty towards her husband. Out of admiration for this woman, the spirit of the mountain turned her into a stone. Her face was made to face the South China Sea, so that she could wait forever for her dear husband's return.\nThe people in her hometown who heard about this were also gravely touched by this. Thus, they decided to name the mountain \"Kinabalu\" in remembrance of her. To them, the mountain is a symbol of the everlasting love and loyalty that should be taken as a good example by women.\nSee also \n- Given the definition of the Malay Archipelago excluding New Guinea, where about 22 mountains exceed 4100 m.\n- \"World Top 50 Most Prominent Peaks\" Peaklist.org. Retrieved 2011-11-21.\n- Phillipps, A. & F. Liew 2000. Globetrotter Visitor's Guide – Kinabalu Park. New Holland Publishers (UK) Ltd.\n- Eight Southeast Asian Destinations You Shouldn't Miss\n- Mount Kinabalu National Park ... revered abode of the dead\n- Parris, B. S., R. S. Beaman, and J. H. Beaman. 1992. The Plants of Mount Kinabalu: 1. Ferns and Fern Allies. Kew: Royal Botanic Gardens. 165 pp + 5 pl.\n- Wood, J. J., J. H. Beaman, and R. S. Beaman. 1993. The Plants of Mount Kinabalu. 2. Orchids. Kew: Royal Botanic Gardens. xii + 411 pp + 84 pl.\n- Beaman, J. H., and R. S. Beaman. 1998. The Plants of Mount Kinabalu. 3. Gymnosperms and Non-Orchid Monocotyledons. Kota Kinabalu: Natural History Publications (Borneo) Sdn. Bhd.; Kew: Royal Botanic Gardens. xii + 220 pp + 25 pl.\n- Beaman, J. H., C. Anderson, and R. S. Beaman. 2001. The plants of Mount Kinabalu. 4: Dicotyledon families Acanthaceae to Lythraceae. xiv + 570 pp + 45 pl. Kota Kinabalu: Natural History Publications (Borneo) Sdn. Bhd.; Kew: Royal Botanic Gardens.\n- Beaman, J. H., and C. Anderson. 2004. The plants of Mount Kinabalu. 5: Dicotyledon families Magnoliaceae to Winteraceae. xiv + 609 pp + 40 pl. Kota Kinabalu: Natural History Publications (Borneo) Sdn. Bhd.; Kew: Royal Botanic Gardens.\n- Kurata, S. 1976. Nepenthes of Mount Kinabalu. Sabah National Parks Publications No. 2, Sabah National Parks Trustees, Kota Kinabalu.\n- Adam, J.H. & C.C. Wilcock 1998 ['1996']. Pitcher plants of Mt. Kinabalu in Sabah. The Sarawak Museum Journal 50(71): 145–171.\n- Blakemore, R.J., C. Csuzdi, M.T. Ito, N. Kaneko, T. Kawaguchi & M. Schilthuizen 2007. PDF (16.4 KiB) Zootaxa 1613: 23–44.\n- \"Kinabalu montane alpine meadows\". Terrestrial Ecoregions. World Wildlife Fund.\n- Hiung, C. S., R. Mandalam, and C. Chin. 2004. The Hugh Low Trail: The Quest for the Historical Trail to the Summit of Kinabalu. The Sabah Society, Kota Kinabalu.\n- Kinabalu Park. UNESCO World Heritage Centre.\n- Cymerman, A; Rock, PB. Medical Problems in High Mountain Environments. A Handbook for Medical Officers. USARIEM-TN94-2. US Army Research Inst. of Environmental Medicine Thermal and Mountain Medicine Division Technical Report. Retrieved 2009-03-05.\n- The Independent, 21 September 1994, Leaders of lost expedition criticised, by Mary Braid\n- McIlroy, N. 2011. Man versus mountain. The West Australian, 9 July 2011.\n|Wikimedia Commons has media related to: Mount Kinabalu|\n- Mount Kinabalu travel guide from Wikivoyage\n- Sabah Parks website\n- Mount Kinabalu Information\n- Climbing Mount Kinabalu\n- Plants of Mount Kinabalu
'''