# -*- coding: utf-8 -*-
"""
Decoy database — large, fabricated university dataset for the honeypot.

Builds a big SQLite file full of completely invented students, staff, courses,
grades, financial records, login accounts, library data and messages. Every row
is bait: it looks like a real, busy university system, but maps to no real
person. A successful SQL-injection "dump" therefore leaks nothing real — it just
gives us a high-fidelity recording of the attacker's technique against a juicy
looking target.

The login query here is INTENTIONALLY built with string concatenation so the
honeypot presents a believable SQL-injection surface. Do NOT copy that pattern
into real software; it is deliberately insecure.

Build it directly with:
    python -m app.decoy_db            # build only if missing / too small
    python -m app.decoy_db --rebuild  # force a fresh large rebuild

Scale is controlled by SCALE below. Defaults produce a multi-table DB with
~15k students and ~350k grade rows (tens of MB). Bump the numbers for more.
"""

import os
import random
import sqlite3

_DB_PATH = os.environ.get(
    "HONEYPOT_DB", os.path.join(os.path.dirname(__file__), "..", "decoy.sqlite")
)

# ---- size knobs -------------------------------------------------------------
SCALE = {
    "students": 15000,
    "instructors": 700,
    "courses": 1000,
    "staff_accounts": 1000,
    "library_books": 5000,
    "loans": 15000,
    "messages": 40000,
    "announcements": 300,
    "exam_rows": 6000,
    "enroll_min": 12, "enroll_max": 34,    # courses per student (history)
    "payments_min": 2, "payments_max": 6,  # payments per student
    "fees_min": 3, "fees_max": 8,          # fee lines per student
}
_MIN_STUDENTS_OK = 5000  # below this we consider the DB "not built"

random.seed(20260609)

# ---- fabricated Arabic content pools ----------------------------------------
MALE = "أحمد محمد محمود خالد عمر علي يوسف إبراهيم عبدالله عبدالرحمن سامي رامي وائل ماجد ناصر زياد طارق هاني باسل كريم مهند أنس مصطفى حسن حسين سعيد جمال كمال نبيل فادي رائد عماد بلال أيمن سليمان داود يعقوب إسماعيل ياسر معتز أشرف عدنان منذر صهيب أوس قصي تميم غسان رضوان نضال جهاد سامح عصام فراس مازن وسيم بشار نزار عاطف منير".split()
FEMALE = "فاطمة عائشة مريم خديجة زينب نور هبة رنا دعاء آلاء إسراء سارة ليلى هدى سمر رهام منى أمل وفاء رغد ميس لينا دينا ربى تالا جنى سلمى ندى شهد بتول رؤى أسيل ميساء روان جواهر إيمان نسرين شيماء أريج بيسان لمى تسنيم رزان غدير حلا ميرا يارا".split()
FAMILY = "العبد أبوندى الأغا شراب مقداد حلس صيدم الفرا النجار الشاعر زقوت مصلح العمري البطش حمدان الريس درويش عاشور المدهون الكحلوت قشطة سكيك الهندي شعت الطويل برهم الخطيب العمصي سلامة زعرب البابا مهنا قنديل أبورمضان حجازي أبوشمالة الجمل عابد المصري نصار حماد أبوعمرة شلدان السقا الوحيدي صالحة جرادة أبوحصيرة الكرد بربخ عقيلان أبوسعدة الزرد أبوهاشم حبيب الرنتيسي أبوشاويش".split()
CITIES = "غزة خانيونس رفح دير_البلح جباليا بيت_لاهيا بيت_حانون النصيرات المغازي البريج عبسان القرارة بني_سهيلا الزوايدة الشجاعية الرمال التفاح الشيخ_رضوان النصر الزيتون".split()
STATUS = ["منتظم", "منتظم", "منتظم", "منتظم", "مؤجل", "خريج", "منسحب", "متوقف عن الدراسة"]
GENDERS = ["ذكر", "أنثى"]
GRADES = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "F"]
GRADE_POINTS = {"A+":4.0,"A":4.0,"A-":3.7,"B+":3.3,"B":3.0,"B-":2.7,"C+":2.3,"C":2.0,"C-":1.7,"D+":1.3,"D":1.0,"F":0.0}
_GRADE_BANDS = [(95,"A+"),(90,"A"),(85,"A-"),(80,"B+"),(75,"B"),(70,"B-"),(65,"C+"),(60,"C"),(55,"C-"),(50,"D+"),(45,"D"),(0,"F")]

def _grade_from(total):
    for lo, g in _GRADE_BANDS:
        if total >= lo:
            return g
    return "F"

FACULTIES = [
    "عمادة الهندسة والنظم الذكية", "عمادة تكنولوجيا المعلومات", "عمادة إدارة الأعمال",
    "عمادة العلوم الصحية والطبية", "عمادة العلوم الإنسانية", "عمادة الإعلام والتصميم",
]
MAJORS = [
    ("تكنولوجيا المعلومات", "بكالوريوس"), ("هندسة الحاسوب", "دبلوم متوسط"),
    ("أمن المعلومات", "دبلوم متوسط"), ("علم الحاسوب", "بكالوريوس"),
    ("هندسة البرمجيات", "بكالوريوس"), ("أنظمة الشبكات", "دبلوم متوسط"),
    ("الوسائط المتعددة", "دبلوم متوسط"), ("إدارة الأعمال", "بكالوريوس"),
    ("المحاسبة", "بكالوريوس"), ("التمويل والمصارف", "بكالوريوس"),
    ("التسويق", "بكالوريوس"), ("نظم المعلومات الإدارية", "بكالوريوس"),
    ("التمريض", "بكالوريوس"), ("القبالة القانونية", "دبلوم متوسط"),
    ("المختبرات الطبية", "بكالوريوس"), ("الصيدلة", "بكالوريوس"),
    ("العلاج الطبيعي", "بكالوريوس"), ("التصوير الطبي", "دبلوم متوسط"),
    ("الهندسة المدنية", "بكالوريوس"), ("الهندسة المعمارية", "بكالوريوس"),
    ("الهندسة الكهربائية", "دبلوم متوسط"), ("هندسة الطاقة المتجددة", "بكالوريوس"),
    ("التصميم الجرافيكي", "دبلوم متوسط"), ("الإعلام الرقمي", "بكالوريوس"),
    ("اللغة الإنجليزية وآدابها", "بكالوريوس"), ("الترجمة الفورية", "دبلوم متوسط"),
]
TITLES = ["أ.د.", "د.", "د.", "م.", "م.", "أ."]
COURSE_PREFIX = ["CS", "SE", "IT", "NET", "SEC", "MM", "BUS", "ACC", "FIN", "MKT",
                 "MIS", "NUR", "MED", "PHR", "PT", "CIV", "ARC", "EE", "ENG", "MATH", "GEN"]
COURSE_TOPICS = [
    "مقدمة في البرمجة", "هياكل البيانات", "الخوارزميات", "قواعد البيانات", "قواعد البيانات المتقدمة",
    "تحليل وتصميم النظم", "هندسة البرمجيات", "هندسة البرمجيات المتقدمة", "شبكات الحاسوب",
    "أمن المعلومات", "التشفير وأمن البيانات", "اختبار الاختراق", "أنظمة التشغيل", "البرمجة الكائنية",
    "برمجة الويب", "تطوير تطبيقات الجوال", "الذكاء الاصطناعي", "تعلم الآلة", "الحوسبة السحابية",
    "إنترنت الأشياء", "الرسوميات الحاسوبية", "الوسائط المتعددة", "نظم إدارة المحتوى",
    "مبادئ المحاسبة", "المحاسبة المتوسطة", "المحاسبة الإدارية", "مبادئ الإدارة", "إدارة المشاريع",
    "السلوك التنظيمي", "مبادئ التسويق", "التسويق الإلكتروني", "الاقتصاد الجزئي", "الاقتصاد الكلي",
    "التمويل الدولي", "إدارة الموارد البشرية", "ريادة الأعمال", "الإحصاء", "الاحتمالات والإحصاء",
    "التفاضل والتكامل", "الجبر الخطي", "الرياضيات المتقطعة", "مبادئ التمريض", "التشريح",
    "علم وظائف الأعضاء", "الكيمياء الحيوية", "علم الأدوية", "الأحياء الدقيقة", "الإسعاف الأولي",
    "مقاومة المواد", "ميكانيكا التربة", "تصميم المنشآت", "الدوائر الكهربائية", "الإلكترونيات",
    "الطاقة الشمسية", "التصميم المعماري", "الرسم الهندسي", "اللغة الإنجليزية", "مهارات الاتصال",
    "الثقافة الإسلامية", "اللغة العربية", "حقوق الإنسان", "مدخل إلى علم النفس",
]
ROOMS = ["A101","A102","A110","A201","A210","B105","B201","B204","C105","C210","Lab1","Lab2","Lab3","Lab4","قاعة المؤتمرات","H1","H2","H3"]
DAYS = ["الأحد/الثلاثاء", "الاثنين/الأربعاء", "السبت", "الخميس", "الأحد/الأربعاء", "الثلاثاء/الخميس"]
TIMES = ["08:00-09:30", "09:30-11:00", "11:00-12:30", "12:30-14:00", "14:00-15:30"]
COMMON_PW = ["123456", "123456789", "password", "ucas2023", "ucas2024", "P@ssw0rd",
             "qwerty123", "11223344", "student2024", "welcome1", "12345678", "iloveucas"]
ROLES = ["registrar", "finance", "faculty", "library", "it_support", "dean_office"]
BOOK_AUTHORS = ["Ian Sommerville","Silberschatz","Kurose & Ross","Stuttard & Pinto","Thomas Cormen",
                "Andrew Tanenbaum","Stallings","Date","Goodrich","Russell & Norvig","عبدالله الزهراني",
                "محمد الشريف","سامي العمري","Bruce Schneier","Kevin Mitnick"]
BOOK_TOPICS = ["Software Engineering","Database System Concepts","Computer Networking","Operating Systems",
               "Information Security","Artificial Intelligence","Data Structures","Cryptography",
               "Web Application Security","Cloud Computing","مدخل إلى البرمجة","قواعد البيانات",
               "أمن الشبكات","تحليل النظم","إدارة المشاريع","المحاسبة المالية","مبادئ التسويق"]
MSG_SENDERS = ["القبول والتسجيل", "الشؤون المالية", "عمادة شؤون الطلبة", "الدعم الفني",
               "المكتبة", "المرشد الأكاديمي", "عمادة الهندسة", "وحدة الامتحانات"]
MSG_SUBJECTS = ["تأكيد تسجيل المواد", "تذكير بالرسوم المستحقة", "تعديل موعد محاضرة",
                "فتح باب التقديم للمنح", "نتائج منتصف الفصل", "تنبيه: آخر موعد للسحب والإضافة",
                "دعوة لورشة عمل", "تحديث بيانات الطالب", "موعد امتحان نهائي", "إشعار حالة الطلب"]


def _name():
    """Return (full_name, gender) with the first name matching the gender."""
    male = random.random() < 0.55
    first = random.choice(MALE if male else FEMALE)
    father = random.choice(MALE)
    grand = random.choice(MALE)
    family = random.choice(FAMILY).replace("_", " ")
    return f"{first} {father} {grand} {family}", ("ذكر" if male else "أنثى")


def _phone():
    return "059" + "".join(random.choice("0123456789") for _ in range(7))


def _national_id():
    return "4" + "".join(random.choice("0123456789") for _ in range(8))


def _password(national_id):
    r = random.random()
    if r < 0.45:
        return random.choice(COMMON_PW)
    if r < 0.65:
        return national_id            # graduates' password is the ID (per portal hint)
    if r < 0.8:
        return random.choice(MALE).encode("ascii", "ignore").decode() or "Pass" + str(random.randint(100, 999))
    return "".join(random.choice("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(random.randint(8, 12)))


# ---- build ------------------------------------------------------------------

def build_database(force: bool = False) -> dict:
    if os.path.exists(_DB_PATH):
        os.remove(_DB_PATH)
    conn = sqlite3.connect(_DB_PATH)
    cur = conn.cursor()
    cur.executescript("""
        PRAGMA journal_mode=OFF;
        PRAGMA synchronous=OFF;
        CREATE TABLE faculties (faculty_id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE majors (major_id INTEGER PRIMARY KEY, name TEXT, degree TEXT,
                             faculty_id INTEGER, required_credits INTEGER);
        CREATE TABLE instructors (instructor_id INTEGER PRIMARY KEY, full_name TEXT,
                             title TEXT, email TEXT, phone TEXT, major_id INTEGER, office TEXT);
        CREATE TABLE students (student_id TEXT PRIMARY KEY, full_name TEXT, username TEXT,
                             password TEXT, national_id TEXT, email TEXT, phone TEXT,
                             gender TEXT, dob TEXT, city TEXT, major TEXT, major_id INTEGER,
                             level INTEGER, gpa REAL, credits_done INTEGER, status TEXT,
                             enroll_year INTEGER, advisor_id INTEGER);
        CREATE TABLE courses (code TEXT PRIMARY KEY, title TEXT, credits INTEGER,
                             major_id INTEGER, level INTEGER);
        CREATE TABLE sections (section_id INTEGER PRIMARY KEY, course_code TEXT,
                             instructor_id INTEGER, semester TEXT, day TEXT, time TEXT,
                             room TEXT, capacity INTEGER);
        CREATE TABLE enrollments (enroll_id INTEGER PRIMARY KEY, student_id TEXT,
                             course_code TEXT, semester TEXT, coursework INTEGER,
                             final INTEGER, total INTEGER, grade TEXT, points REAL);
        CREATE TABLE fees (fee_id INTEGER PRIMARY KEY, student_id TEXT, semester TEXT,
                             description TEXT, amount REAL, type TEXT);
        CREATE TABLE payments (payment_id INTEGER PRIMARY KEY, student_id TEXT, date TEXT,
                             amount REAL, method TEXT, reference TEXT);
        CREATE TABLE accounts (account_id INTEGER PRIMARY KEY, username TEXT, password TEXT,
                             role TEXT, full_name TEXT, email TEXT, last_login TEXT, is_active INTEGER);
        CREATE TABLE library_books (book_id INTEGER PRIMARY KEY, title TEXT, author TEXT,
                             isbn TEXT, call_number TEXT, copies INTEGER, available INTEGER);
        CREATE TABLE loans (loan_id INTEGER PRIMARY KEY, student_id TEXT, book_id INTEGER,
                             borrow_date TEXT, due_date TEXT, returned INTEGER);
        CREATE TABLE announcements (id INTEGER PRIMARY KEY, title TEXT, body TEXT,
                             source TEXT, date TEXT);
        CREATE TABLE messages (id INTEGER PRIMARY KEY, student_id TEXT, sender TEXT,
                             subject TEXT, body TEXT, date TEXT, is_read INTEGER);
        CREATE TABLE exam_schedule (id INTEGER PRIMARY KEY, course_code TEXT, semester TEXT,
                             date TEXT, time TEXT, hall TEXT, seat INTEGER);
    """)

    # faculties
    cur.executemany("INSERT INTO faculties VALUES (?,?)",
                    [(i + 1, FACULTIES[i]) for i in range(len(FACULTIES))])

    # majors
    majors = []
    for i, (nm, deg) in enumerate(MAJORS, start=1):
        majors.append((i, nm, deg, random.randint(1, len(FACULTIES)),
                       132 if deg == "بكالوريوس" else 72))
    cur.executemany("INSERT INTO majors VALUES (?,?,?,?,?)", majors)
    major_ids = [m[0] for m in majors]
    major_name = {m[0]: m[1] for m in majors}

    # instructors
    instr = []
    for i in range(1, SCALE["instructors"] + 1):
        nm, _ = _name()
        mid = random.choice(major_ids)
        instr.append((i, nm, random.choice(TITLES),
                      f"instructor{i}@ucas.edu.ps", _phone(), mid,
                      f"{random.choice('ABCDE')}{random.randint(1,4)}{random.randint(0,9)}{random.randint(0,9)}"))
    cur.executemany("INSERT INTO instructors VALUES (?,?,?,?,?,?,?)", instr)
    instr_ids = [r[0] for r in instr]

    # courses
    courses = []
    used = set()
    for i in range(SCALE["courses"]):
        pre = random.choice(COURSE_PREFIX)
        num = random.randint(101, 499)
        code = f"{pre}{num}"
        while code in used:
            num = random.randint(101, 499)
            code = f"{pre}{num}"
        used.add(code)
        courses.append((code, random.choice(COURSE_TOPICS), random.choice([2, 3, 3, 3, 4]),
                        random.choice(major_ids), num // 100))
    cur.executemany("INSERT INTO courses VALUES (?,?,?,?,?)", courses)
    course_codes = [c[0] for c in courses]

    # sections
    semesters = ["2023/2024 الأول", "2023/2024 الثاني", "2024/2025 الأول",
                 "2024/2025 الثاني", "2025/2026 الأول", "2025/2026 الثاني"]
    sections = []
    sid = 1
    for code in course_codes:
        for _ in range(random.randint(1, 4)):
            sections.append((sid, code, random.choice(instr_ids), random.choice(semesters),
                             random.choice(DAYS), random.choice(TIMES), random.choice(ROOMS),
                             random.choice([25, 30, 35, 40, 45])))
            sid += 1
    cur.executemany("INSERT INTO sections VALUES (?,?,?,?,?,?,?,?)", sections)

    # students  (+ their enrollments / fees / payments)
    students, enrollments, fees, payments = [], [], [], []
    all_sids = []
    eid = fid = pid = 1
    fee_types = ["رسوم تسجيل", "رسوم ساعات معتمدة", "رسوم خدمات", "رسوم امتحانات", "غرامة تأخير"]
    pay_methods = ["تحويل بنكي", "دفع نقدي", "بطاقة ائتمان", "صراف آلي", "حوالة"]
    for n in range(SCALE["students"]):
        year = random.choice([2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025])
        sidn = f"{year-2000+100}{n:06d}"   # unique, e.g. 120000123
        all_sids.append(sidn)
        mid = random.choice(major_ids)
        nid = _national_id()
        full_name, gender = _name()
        gpa = round(random.uniform(60, 96), 2)
        done = random.randint(0, 132)
        username = sidn if random.random() < 0.5 else f"s{sidn}"
        students.append((sidn, full_name, username or sidn, _password(nid), nid,
                         f"{sidn}@smail.ucas.edu.ps", _phone(), gender,
                         f"{random.randint(1998,2006)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
                         random.choice(CITIES).replace("_", " "), major_name[mid], mid,
                         random.randint(1, 5), gpa, done, random.choice(STATUS), year,
                         random.choice(instr_ids)))
        # enrollments
        k = random.randint(SCALE["enroll_min"], SCALE["enroll_max"])
        for code in random.sample(course_codes, min(k, len(course_codes))):
            cw = random.randint(15, 40); fn = random.randint(15, 60)
            tot = min(100, cw + fn); g = _grade_from(tot)
            enrollments.append((eid, sidn, code, random.choice(semesters), cw, fn, tot, g, GRADE_POINTS[g]))
            eid += 1
        # fees
        for _ in range(random.randint(SCALE["fees_min"], SCALE["fees_max"])):
            fees.append((fid, sidn, random.choice(semesters), random.choice(fee_types),
                         round(random.choice([150, 300, 450, 600, 900, 1200]) * random.uniform(.8, 1.5), 2),
                         "مستحق" if random.random() < .4 else "مدفوع"))
            fid += 1
        # payments
        for _ in range(random.randint(SCALE["payments_min"], SCALE["payments_max"])):
            payments.append((pid, sidn, f"{random.choice([2023,2024,2025,2026])}-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
                             round(random.uniform(200, 2400), 2), random.choice(pay_methods),
                             "REF" + "".join(random.choice("0123456789") for _ in range(8))))
            pid += 1
        if len(students) >= 2000:
            cur.executemany("INSERT INTO students VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", students)
            cur.executemany("INSERT INTO enrollments VALUES (?,?,?,?,?,?,?,?,?)", enrollments)
            cur.executemany("INSERT INTO fees VALUES (?,?,?,?,?,?)", fees)
            cur.executemany("INSERT INTO payments VALUES (?,?,?,?,?,?)", payments)
            students, enrollments, fees, payments = [], [], [], []
    if students:
        cur.executemany("INSERT INTO students VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", students)
        cur.executemany("INSERT INTO enrollments VALUES (?,?,?,?,?,?,?,?,?)", enrollments)
        cur.executemany("INSERT INTO fees VALUES (?,?,?,?,?,?)", fees)
        cur.executemany("INSERT INTO payments VALUES (?,?,?,?,?,?)", payments)

    # staff / admin accounts (high-value bait)
    accounts = [(1, "admin", "Admin@ucas2024", "superadmin", "مدير النظام",
                 "admin@ucas.edu.ps", "2026-06-08 22:14:03", 1)]
    for i in range(2, SCALE["staff_accounts"] + 1):
        role = random.choice(ROLES)
        accounts.append((i, f"{role}{random.randint(1,99)}", random.choice(COMMON_PW), role,
                         _name()[0], f"{role}{i}@ucas.edu.ps",
                         f"2026-0{random.randint(1,6)}-{random.randint(1,28):02d} {random.randint(7,20):02d}:{random.randint(0,59):02d}:00",
                         random.choice([1, 1, 1, 0])))
    cur.executemany("INSERT INTO accounts VALUES (?,?,?,?,?,?,?,?)", accounts)

    # library
    books = []
    for i in range(1, SCALE["library_books"] + 1):
        copies = random.randint(1, 8)
        books.append((i, f"{random.choice(BOOK_TOPICS)} ({random.randint(1,9)}th ed.)",
                      random.choice(BOOK_AUTHORS),
                      "978" + "".join(random.choice("0123456789") for _ in range(10)),
                      f"QA{random.randint(70,99)}.{random.randint(1,9)} {random.choice('ABCDEFGH')}{random.randint(1,9)}",
                      copies, random.randint(0, copies)))
    cur.executemany("INSERT INTO library_books VALUES (?,?,?,?,?,?,?)", books)

    # loans
    loans = []
    for i in range(1, SCALE["loans"] + 1):
        loans.append((i, random.choice(all_sids),
                      random.randint(1, SCALE["library_books"]),
                      f"2026-0{random.randint(1,6)}-{random.randint(1,28):02d}",
                      f"2026-0{random.randint(1,6)}-{random.randint(1,28):02d}",
                      random.choice([0, 1])))
    cur.executemany("INSERT INTO loans VALUES (?,?,?,?,?,?)", loans)

    # announcements
    anns = []
    for i in range(1, SCALE["announcements"] + 1):
        anns.append((i, random.choice(MSG_SUBJECTS), "نص الإعلان التجريبي رقم %d لأغراض النظام." % i,
                     random.choice(MSG_SENDERS),
                     f"2026-0{random.randint(1,6)}-{random.randint(1,28):02d}"))
    cur.executemany("INSERT INTO announcements VALUES (?,?,?,?,?)", anns)

    # messages
    msgs = []
    for i in range(1, SCALE["messages"] + 1):
        msgs.append((i, random.choice(all_sids),
                     random.choice(MSG_SENDERS), random.choice(MSG_SUBJECTS),
                     "هذه رسالة تجريبية ضمن النظام لأغراض العرض.",
                     f"2026-0{random.randint(1,6)}-{random.randint(1,28):02d}", random.choice([0, 1])))
    cur.executemany("INSERT INTO messages VALUES (?,?,?,?,?,?,?)", msgs)

    # exam schedule
    exams = []
    halls = ["قاعة A", "قاعة B", "قاعة C", "مختبر 1", "مختبر 2", "قاعة المؤتمرات"]
    for i in range(1, SCALE["exam_rows"] + 1):
        exams.append((i, random.choice(course_codes), random.choice(semesters),
                      f"2026-06-{random.randint(10,28):02d}", random.choice(TIMES),
                      random.choice(halls), random.randint(1, 60)))
    cur.executemany("INSERT INTO exam_schedule VALUES (?,?,?,?,?,?,?)", exams)

    # indexes
    cur.executescript("""
        CREATE INDEX idx_enr_student ON enrollments(student_id);
        CREATE INDEX idx_enr_course  ON enrollments(course_code);
        CREATE INDEX idx_pay_student ON payments(student_id);
        CREATE INDEX idx_fee_student ON fees(student_id);
        CREATE INDEX idx_stu_user    ON students(username);
    """)
    conn.commit()

    stats = {t: cur.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in
             ("faculties", "majors", "instructors", "students", "courses", "sections",
              "enrollments", "fees", "payments", "accounts", "library_books", "loans",
              "announcements", "messages", "exam_schedule")}
    conn.close()
    return stats


def init_db() -> None:
    """Build the decoy DB once; reuse it on later startups (it is large)."""
    need = True
    if os.path.exists(_DB_PATH):
        try:
            c = sqlite3.connect(_DB_PATH)
            n = c.execute("SELECT COUNT(*) FROM students").fetchone()[0]
            c.close()
            need = n < _MIN_STUDENTS_OK
        except sqlite3.Error:
            need = True
    if need:
        build_database(force=True)


def _connect() -> sqlite3.Connection:
    # Read-only handle: the injectable queries can READ the decoy bait but can
    # never modify the database, no matter what an attacker injects.
    import pathlib
    uri = pathlib.Path(_DB_PATH).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def vulnerable_login(username: str, password: str):
    """Deliberately injectable login. Returns (rows, executed_sql)."""
    sql = (
        "SELECT student_id, full_name, major, gpa FROM students "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    conn = _connect()
    try:
        try:
            rows = [dict(r) for r in conn.execute(sql).fetchall()[:200]]
        except sqlite3.Error as exc:
            return {"error": str(exc)}, sql
        return rows, sql
    finally:
        conn.close()


def vulnerable_grade_lookup(student_id: str):
    """Second injectable surface: grade lookup by student id."""
    sql = (
        "SELECT e.course_code, c.title, e.grade FROM enrollments e "
        "JOIN courses c ON c.code = e.course_code "
        f"WHERE e.student_id = '{student_id}'"
    )
    conn = _connect()
    try:
        try:
            rows = [dict(r) for r in conn.execute(sql).fetchall()[:500]]
        except sqlite3.Error as exc:
            return {"error": str(exc)}, sql
        return rows, sql
    finally:
        conn.close()


if __name__ == "__main__":
    import sys
    import time
    force = "--rebuild" in sys.argv
    if force or not os.path.exists(_DB_PATH):
        t = time.time()
        print("building large decoy database ...")
        s = build_database(force=True)
        size = os.path.getsize(_DB_PATH) / (1024 * 1024)
        print(f"done in {time.time()-t:.1f}s  —  {size:.1f} MB")
        for k, v in s.items():
            print(f"  {k:16} {v:>10,}")
    else:
        init_db()
        print("decoy DB already present; pass --rebuild to regenerate.")
