"""
Fabricated display content for the portal pages.

Everything here is invented decoy data for the honeypot UI. No real person,
roster, schedule or financial record. Keeping it in one module makes the routes
in honeypot.py thin and easy to read.
"""

PROFILE = {
    "name": "أحمد محمد العبد",
    "sid": "20211045",
    "national_id": "40•••••••2",
    "dob": "2003-04-17",
    "nationality": "فلسطيني",
    "gender": "ذكر",
    "email": "ahmad.20211045@student.uni.edu",
    "phone": "059•••••12",
    "address": "غزة - الرمال",
    "faculty": "كلية تكنولوجيا المعلومات",
    "major": "هندسة البرمجيات",
}

CURRENT_COURSES = [
    {"code": "SE331", "title": "هندسة البرمجيات 2", "credits": 3, "instructor": "د. سامي حلس", "room": "B204", "section": 1},
    {"code": "CS342", "title": "قواعد البيانات المتقدمة", "credits": 3, "instructor": "د. منى أبو ندى", "room": "A110", "section": 2},
    {"code": "CS361", "title": "أمن المعلومات", "credits": 3, "instructor": "د. خالد شراب", "room": "Lab3", "section": 1},
    {"code": "CS350", "title": "شبكات الحاسوب", "credits": 3, "instructor": "د. أحمد مقداد", "room": "B201", "section": 1},
    {"code": "MATH301", "title": "الاحتمالات والإحصاء", "credits": 3, "instructor": "د. رائد صيدم", "room": "C105", "section": 3},
]

AVAILABLE_COURSES = [
    {"code": "CS410", "title": "الذكاء الاصطناعي", "credits": 3, "section": 1},
    {"code": "CS422", "title": "تطوير تطبيقات الويب", "credits": 3, "section": 2},
    {"code": "CS430", "title": "الحوسبة السحابية", "credits": 3, "section": 1},
    {"code": "SE440", "title": "إدارة مشاريع البرمجيات", "credits": 3, "section": 1},
    {"code": "CS455", "title": "تعلم الآلة", "credits": 3, "section": 1},
]

# Weekly schedule: 5 days x 4 slots. None = free slot.
def _c(code):
    for c in CURRENT_COURSES:
        if c["code"] == code:
            return {"code": c["code"], "title": c["title"], "room": c["room"]}
    return None

WEEK = [
    ("السبت",   [_c("SE331"), _c("CS342"), None,        _c("CS361")]),
    ("الأحد",   [_c("CS350"), None,        _c("MATH301"), None]),
    ("الإثنين", [_c("SE331"), _c("CS342"), None,        _c("CS361")]),
    ("الثلاثاء",[_c("CS350"), None,        _c("MATH301"), None]),
    ("الأربعاء",[None,        _c("CS361"), None,        None]),
]

GRADES = [
    {"code": "SE331", "title": "هندسة البرمجيات 2", "cw": 28, "final": 52, "total": 80, "grade": "A-"},
    {"code": "CS342", "title": "قواعد البيانات المتقدمة", "cw": 25, "final": 48, "total": 73, "grade": "B+"},
    {"code": "CS361", "title": "أمن المعلومات", "cw": 30, "final": 58, "total": 88, "grade": "A"},
    {"code": "CS350", "title": "شبكات الحاسوب", "cw": 22, "final": 41, "total": 63, "grade": "C+"},
    {"code": "MATH301", "title": "الاحتمالات والإحصاء", "cw": 24, "final": 45, "total": 69, "grade": "B"},
]

ANNOUNCEMENTS = [
    {"title": "بدء فترة التسجيل للفصل الصيفي", "body": "تُفتح فترة التسجيل للفصل الصيفي اعتباراً من 2026/06/15.",
     "source": "القبول والتسجيل", "date": "2026-06-05"},
    {"title": "موعد تسليم مشاريع التخرج", "body": "آخر موعد لتسليم النسخة النهائية من مشروع التخرج هو 2026/06/25.",
     "source": "كلية تكنولوجيا المعلومات", "date": "2026-06-03"},
    {"title": "صيانة مجدولة للنظام", "body": "سيتوقف النظام للصيانة يوم الجمعة من 12 ص حتى 4 ص.",
     "source": "الدعم الفني", "date": "2026-06-01"},
    {"title": "ورشة عمل: مقدمة في الأمن السيبراني", "body": "ورشة مجانية لطلبة الكلية يوم الأحد القادم في قاعة المؤتمرات.",
     "source": "نادي الحاسوب", "date": "2026-05-28"},
    {"title": "تنبيه بشأن الرسوم", "body": "يُرجى تسديد الرسوم المستحقة قبل بدء الامتحانات النهائية.",
     "source": "الشؤون المالية", "date": "2026-05-25"},
]

FINANCE = {
    "total": 4800, "paid": 3600, "due": 1200,
    "transactions": [
        {"date": "2025-09-10", "desc": "رسوم الفصل الأول", "debit": "2400", "credit": "—", "balance": "2400"},
        {"date": "2025-09-12", "desc": "دفعة نقدية", "debit": "—", "credit": "1800", "balance": "600"},
        {"date": "2026-02-08", "desc": "رسوم الفصل الثاني", "debit": "2400", "credit": "—", "balance": "3000"},
        {"date": "2026-02-15", "desc": "دفعة - تحويل بنكي", "debit": "—", "credit": "1800", "balance": "1200"},
    ],
}

EXAMS = [
    {"code": "SE331", "title": "هندسة البرمجيات 2", "date": "2026-06-14", "day": "الأحد", "time": "09:00", "hall": "قاعة A", "seat": "42"},
    {"code": "CS342", "title": "قواعد البيانات المتقدمة", "date": "2026-06-16", "day": "الثلاثاء", "time": "11:30", "hall": "قاعة B", "seat": "17"},
    {"code": "CS361", "title": "أمن المعلومات", "date": "2026-06-18", "day": "الخميس", "time": "09:00", "hall": "مختبر 3", "seat": "08"},
    {"code": "CS350", "title": "شبكات الحاسوب", "date": "2026-06-21", "day": "الأحد", "time": "13:00", "hall": "قاعة A", "seat": "42"},
    {"code": "MATH301", "title": "الاحتمالات والإحصاء", "date": "2026-06-23", "day": "الثلاثاء", "time": "09:00", "hall": "قاعة C", "seat": "55"},
]

INBOX = [
    {"sender": "القبول والتسجيل", "subject": "تأكيد تسجيل مواد الفصل", "date": "2026-06-04", "unread": True},
    {"sender": "د. خالد شراب", "subject": "تعديل موعد محاضرة أمن المعلومات", "date": "2026-06-02", "unread": True},
    {"sender": "الشؤون المالية", "subject": "تذكير بالرسوم المستحقة", "date": "2026-05-30", "unread": False},
    {"sender": "عمادة شؤون الطلبة", "subject": "فتح باب التقديم للمنح", "date": "2026-05-26", "unread": False},
]

BOOKS = [
    {"title": "Software Engineering (Sommerville)", "author": "Ian Sommerville", "call": "QA76.758 S6", "available": True},
    {"title": "Database System Concepts", "author": "Silberschatz", "call": "QA76.9 D3", "available": False},
    {"title": "Computer Networking: A Top-Down Approach", "author": "Kurose & Ross", "call": "TK5105 K8", "available": True},
    {"title": "The Web Application Hacker's Handbook", "author": "Stuttard & Pinto", "call": "QA76.9 A25", "available": True},
]

LOANS = [
    {"title": "Database System Concepts", "from": "2026-05-20", "due": "2026-06-20"},
]

STUDY_PLAN = [
    {"name": "السنة الأولى - الفصل الأول", "status": "مجتاز", "badge_class": "b-ok", "courses": [
        {"code": "CS101", "title": "مقدمة في البرمجة", "credits": 3, "prereq": None, "state": "ناجح", "cls": "b-ok"},
        {"code": "MATH101", "title": "تفاضل وتكامل 1", "credits": 3, "prereq": None, "state": "ناجح", "cls": "b-ok"},
        {"code": "ENG101", "title": "لغة إنجليزية 1", "credits": 3, "prereq": None, "state": "ناجح", "cls": "b-ok"},
    ]},
    {"name": "السنة الثانية - الفصل الأول", "status": "مجتاز", "badge_class": "b-ok", "courses": [
        {"code": "CS210", "title": "هياكل البيانات", "credits": 3, "prereq": "CS101", "state": "ناجح", "cls": "b-ok"},
        {"code": "CS220", "title": "البرمجة الكائنية", "credits": 3, "prereq": "CS101", "state": "ناجح", "cls": "b-ok"},
    ]},
    {"name": "السنة الثالثة - الفصل الحالي", "status": "قيد الدراسة", "badge_class": "b-info", "courses": [
        {"code": "SE331", "title": "هندسة البرمجيات 2", "credits": 3, "prereq": "CS220", "state": "مسجّل", "cls": "b-info"},
        {"code": "CS361", "title": "أمن المعلومات", "credits": 3, "prereq": "CS350", "state": "مسجّل", "cls": "b-info"},
    ]},
    {"name": "السنة الرابعة", "status": "متبقٍ", "badge_class": "b-warn", "courses": [
        {"code": "CS499", "title": "مشروع التخرج", "credits": 6, "prereq": "SE331", "state": "متبقٍ", "cls": "b-warn"},
        {"code": "CS455", "title": "تعلم الآلة", "credits": 3, "prereq": "MATH301", "state": "متبقٍ", "cls": "b-warn"},
    ]},
]
