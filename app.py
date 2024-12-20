from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import os
import datetime
import random
import signal

def handle_sigterm(*args):
    print("Received SIGTERM, shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGINT, handle_sigterm)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

def get_db_connection():
    if 'role' in session and session['role'] == 'админ':
        db_user = os.getenv('DB_ADMIN_USER')
        db_password = os.getenv('DB_ADMIN_PASSWORD')
    else:
        db_user = os.getenv('DB_NORMAL_USER')
        db_password = os.getenv('DB_NORMAL_USER_PASSWORD')

    return psycopg2.connect(
        host=os.getenv('DB_HOST'),
        database=os.getenv('DB_NAME'),
        user=db_user,
        password=db_password,
        cursor_factory=RealDictCursor
    )

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    role = session.get('role', 'обычный')

    conn = get_db_connection()
    cur = conn.cursor()

    if role == 'админ':
        cur.execute("SELECT * FROM subjects")
    else:
        cur.execute("""
            SELECT * FROM subjects 
            WHERE openness = 'публичный' OR creator_id = %s
            """,
            (user_id,))

    subjects = cur.fetchall()
    cur.close()

    return render_template('index.html', subjects=subjects, role=role, username=session['username'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = 'обычный'

        if password != confirm_password:
            flash("Пароли не совпадают", 'danger')
            return redirect(url_for('register'))

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SAVEPOINT register_savepoint")

        try:

            cur.execute("SELECT * FROM users WHERE login = %s", (username,))
            user = cur.fetchone()

            if user:
                flash("Пользователь с таким логином уже существует", 'danger')
                cur.execute("ROLLBACK TO SAVEPOINT register_savepoint")
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password)

            cur.execute("INSERT INTO users (login, password, role) VALUES (%s, %s, %s) RETURNING id", (username, hashed_password, role))
            user_id = cur.fetchone()['id']

            conn.commit()
            cur.close()

            session['user_id'] = user_id
            session['username'] = username
            session['role'] = role

            flash("Регистрация прошла успешно", 'success')
            return redirect(url_for('index'))

        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT register_savepoint")
            flash(f"Ошибка регистрации: {str(e)}", 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE login = %s", (username,))
        user = cur.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['login']
            session['role'] = user['role']
            
            conn.commit()
            cur.close()

            flash("Добро пожаловать!", 'success')
            return redirect(url_for('index'))
        else:
            flash("Неверный логин или пароль", 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash("Вы вышли из системы", 'info')
    return redirect(url_for('login'))

@app.route('/add_subject', methods=['GET', 'POST'])
def add_subject():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        openness = request.form['openness']
        user_id = session['user_id']

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("INSERT INTO subjects (creator_id, openness, name, description) VALUES (%s, %s, %s, %s)",
            (user_id, openness, name, description))

        conn.commit()
        cur.close()

        flash("Предмет успешно добавлен!", "success")
        return redirect(url_for('index'))

    return render_template('add_subject.html')

@app.route('/users')
def users():
    if 'user_id' not in session or session.get('role') != 'админ':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, login, role FROM users")
    users = cur.fetchall()
    cur.close()

    return render_template('users.html', users=users)
    
@app.route('/actions')
def actions():
    if 'user_id' not in session or session.get('role') != 'админ':
        return redirect(url_for('login'))

    search_query = request.args.get('search', '')

    conn = get_db_connection()
    cur = conn.cursor()

    if search_query:
        cur.execute("SELECT * FROM action_logs WHERE details ILIKE %s ORDER BY timestamp DESC",
            ('%' + search_query + '%',))
    else:
        cur.execute("SELECT * FROM action_logs ORDER BY timestamp DESC")

    action_logs = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('actions.html', action_logs=action_logs)

@app.route('/question-history')
def question_history():
    if 'user_id' not in session or session.get('role') != 'админ':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM question_history_view ORDER BY answer_time DESC")
    question_history_data = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('question_history.html', data=question_history_data)

@app.route('/subject/<int:subject_id>')
def subject_page(subject_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    role = session['role']

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM subjects WHERE id = %s", (subject_id,))
    subject = cur.fetchone()

    if not subject:
        cur.close()
        return "Предмет не найден", 404

    if subject['openness'] == 'закрытый' and subject['creator_id'] != user_id and role != 'админ':
        cur.close()
        return "Доступ запрещен", 403

    cur.execute("""
        SELECT assignments.*, COUNT(questions.id) AS question_count
        FROM assignments
        LEFT JOIN questions ON questions.assignment_id = assignments.id
        WHERE assignments.subject_id = %s
        GROUP BY assignments.id
    """, (subject_id,))
    assignments = cur.fetchall()

    is_creator = (subject['creator_id'] == user_id)

    cur.close()

    return render_template(
        'subject.html',
        subject=subject,
        assignments=assignments,
        is_creator=is_creator,
        role=session.get('role', 'обычный')
    )

@app.route('/subject/<int:subject_id>/delete', methods=['POST'])
def delete_subject(subject_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    role = session['role']

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT creator_id FROM subjects WHERE id = %s", (subject_id,))
    subject = cur.fetchone()

    if not subject:
        cur.close()
        return "Предмет не найден", 404

    if subject['creator_id'] != user_id and role != 'админ':
        cur.close()
        return "Доступ запрещен", 403

    cur.execute("DELETE FROM subjects WHERE id = %s", (subject_id,))
    conn.commit()
    cur.close()

    return redirect(url_for('index'))

@app.route('/subject/<int:subject_id>/toggle', methods=['POST'])
def toggle_subject_openness(subject_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    role = session['role']

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT creator_id, openness FROM subjects WHERE id = %s", (subject_id,))
    subject = cur.fetchone()

    if not subject:
        cur.close()
        return "Предмет не найден", 404

    if subject['creator_id'] != user_id and role != 'админ':
        cur.close()
        return "Доступ запрещен", 403

    new_openness = 'закрытый' if subject['openness'] == 'публичный' else 'публичный'
    cur.execute("UPDATE subjects SET openness = %s WHERE id = %s", (new_openness, subject_id))

    conn.commit()
    cur.close()

    return redirect(url_for('subject_page', subject_id=subject_id))

@app.route('/subject/<int:subject_id>/add_assignment', methods=['GET', 'POST'])
def add_assignment(subject_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_id = session['user_id']
        role = session['role']

        assignment_name = request.form['name']

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT creator_id, openness FROM subjects WHERE id = %s", (subject_id,))
        subject = cur.fetchone()

        if subject['creator_id'] != user_id and role != 'админ':
            cur.close()
            return "Доступ запрещен", 403

        cur.execute("INSERT INTO assignments (name, subject_id) VALUES (%s, %s)", (assignment_name, subject_id))
        conn.commit()
        cur.close()

        return redirect(url_for('subject_page', subject_id=subject_id))

    return render_template('add_assignment.html', subject_id=subject_id)

@app.route('/assignment/<int:assignment_id>', methods=['GET', 'POST'])
def assignment_page(assignment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    role = session['role']

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT name, subject_id FROM assignments WHERE id = %s", (assignment_id,))
    assignment = cur.fetchone()

    if not assignment:
        cur.close()
        return "Задание не найдено", 404

    assignment_name = assignment['name']
    subject_id = assignment['subject_id']

    cur.execute("SELECT * FROM subjects WHERE id = %s", (subject_id,))
    subject = cur.fetchone()

    if subject['openness'] == 'закрытый' and subject['creator_id'] != user_id and role != 'админ':
        cur.close()
        return "Доступ запрещен", 403

    is_creator = subject['creator_id'] == user_id

    cur.execute("SELECT id, question_text FROM questions WHERE assignment_id = %s", (assignment_id,))
    questions = cur.fetchall()
    total_questions = len(questions)

    if not total_questions:
        progress_percentage = 0
        correct_answered = 0
    else:
        stats = get_stat_questions(questions, user_id, assignment_id)

        correct_answered = sum(1 for question in stats if question['stat'] > 80)

        progress_percentage = round((correct_answered / total_questions) * 100, 2)


    correct_answer_text = []
    is_correct = None

    if request.method == 'POST':
        question_id = request.form.get('question_id')
        user_answers = request.form.getlist('answers')

        cur.execute("SELECT * FROM questions WHERE id = %s", (question_id,))
        question = cur.fetchone()

        cur.execute("""INSERT INTO question_history (user_id, is_in_progress) 
            VALUES (%s, TRUE) RETURNING id
            """, 
            (user_id,)
        )
        question_history_id = cur.fetchone()['id']

        for answer_id in user_answers:
            cur.execute(
                "INSERT INTO answer_history (question_history_id, answer_id) VALUES (%s, %s)",
                (question_history_id, answer_id)
                )

        cur.execute("""
        SELECT qhv.is_correct AS is_right
            FROM question_history_view qhv
            WHERE qhv.user_id = %s AND qhv.question_history_id = %s AND qhv.is_in_progress = TRUE
            """,
            (user_id, question_history_id)
            )
        result = cur.fetchone()

        is_correct = result['is_right']

        conn.commit()

        return render_template(
            'assignment.html',
            assignment_id=assignment_id,
            assignment_name=assignment_name,

            progress_percentage=progress_percentage,
            correct_answers=correct_answered,
            total_answers=total_questions,

            subject=subject,
            question=None,
            answers=None,

            correct_answer_text=question['correct_answer_text'],
            is_correct=is_correct,
            role=role,
            is_creator=is_creator,

        )

    random_question = None
    answers = None

    if questions:
        random_question = pick_random_question(stats,questions, user_id)
        random_question['question_text'] = random_question['question_text'].replace('&', "<br>")
        cur.execute("SELECT id, answer_text, status FROM answers WHERE question_id = %s", (random_question['id'],))
        answers = cur.fetchall()
        answers.sort(key=lambda x: x['answer_text'])


    cur.close()

    return render_template(
        'assignment.html',
        assignment_id=assignment_id,
        assignment_name=assignment_name,

        progress_percentage=progress_percentage,
        correct_answers=correct_answered,
        total_answers=total_questions,


        subject=subject,
        question=random_question,
        answers=answers,

        correct_answer_text=None,
        is_correct=None,
        role=role,
        is_creator=is_creator,
        )

def get_stat_questions(questions, user_id, assignment_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
    """
         SELECT question_history_view.question_id, question_history_view.is_correct AS is_right
        FROM question_history_view 
        WHERE question_history_view.user_id = %s AND question_history_view.assignment_id = %s
             AND question_history_view.is_in_progress = TRUE
        """,
        (user_id, assignment_id))
    progress = cur.fetchall()

    stat_questions = []
    for question in questions:
        question_id = question['id']
        
        question_progress = [record for record in progress if record['question_id'] == question_id]
        
        if question_progress:
            true_answers = sum(record['is_right'] for record in question_progress)
            wrong_answers = len(question_progress) - true_answers

            if wrong_answers == 0:
                question['stat'] = 100
            else:
                question['stat'] = true_answers * 100 / (wrong_answers + true_answers)
        else:
            question['stat'] = 0  

        stat_questions.append(question)

    stat_questions.sort(key=lambda a: a['stat'])

    cur.close()
    conn.close()

    return stat_questions

def pick_random_question(stats, questions,user_id):
    question_stats = dict()
    for qs in stats:
        question_stats[qs['id']] = qs

    while True:
        random_question = random.choice(questions)
        question_stat = question_stats.get(random_question['id'], None)
        if not question_stat:
            return random_question
        else:
            rqs = random_question['stat']

            if rqs <= 63: 
                return random_question
            else:
                c_rand = (300 / (rqs - 60)) - 0.5 * rqs + 45
                if random.randint(1, 99) < c_rand:
                    return random_question   

@app.route('/assignment/<int:assignment_id>/reset', methods=['POST'])
def reset_progress(assignment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("CALL reset_question_history(%s, %s)", (user_id, assignment_id))

    conn.commit()
    cur.close()

    return redirect(url_for('assignment_page', assignment_id=assignment_id))


@app.route('/assignment/<int:assignment_id>/delete', methods=['POST'])
def delete_assignment(assignment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    role = session.get('role')

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""SELECT subject_id, subjects.creator_id FROM assignments
                JOIN subjects ON assignments.subject_id = subjects.id 
                WHERE assignments.id = %s""", (assignment_id,))
    creator = cur.fetchone()

    if not creator:
        cur.close()
        return "Задание не найдено", 404

    if creator['creator_id'] != user_id and role != 'админ':
        cur.close()
        return "Доступ запрещен", 403

    cur.execute("DELETE FROM assignments WHERE id = %s", (assignment_id,))
    conn.commit()
    cur.close()

    return redirect(url_for('subject_page', subject_id=creator['subject_id']))


@app.route('/assignment/<int:assignment_id>/statistics')
def statistics(assignment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, question_text FROM questions WHERE assignment_id = %s",
        (assignment_id,)
        )
    questions = cur.fetchall()

    stat_questions = get_stat_questions(questions, user_id, assignment_id)
    stat_questions.sort(key=lambda a: a['stat'], reverse=True)

    cur.execute("""
        SELECT name FROM assignments 
        WHERE id = %s
        """,
        (assignment_id,)
    )
    assignment = cur.fetchone()

    if not assignment:
        cur.close()
        return "Задание не найдено", 404

    assignment_name = assignment['name']

    cur.close()

    return render_template(
        'statistics.html',
        assignment_id=assignment_id,
        assignment_name=assignment_name,
        stat_questions=stat_questions
    )

@app.route('/assignment/<int:assignment_id>/edit', methods=['GET', 'POST'])
def edit_assignment(assignment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()

    user_id = session['user_id']
    role = session.get('role')

    cur.execute("""SELECT subject_id, subjects.creator_id FROM assignments
                JOIN subjects ON assignments.subject_id = subjects.id 
                WHERE assignments.id = %s""", (assignment_id,))
    creator = cur.fetchone()

    if creator['creator_id'] != user_id and role != 'админ':
        cur.close()
        return "Доступ запрещен", 403

    cur.execute("""
        SELECT q.id AS question_id, q.question_text, q.correct_answer_text, 
            ARRAY_AGG(a.answer_text) AS answers, 
               ARRAY_AGG(CASE WHEN a.status = 'правильный' THEN 1 ELSE 0 END) AS answer_statuses
        FROM questions q
        LEFT JOIN answers a ON q.id = a.question_id
        WHERE q.assignment_id = %s
        GROUP BY q.id
        """,(assignment_id,)
    )

    questions = cur.fetchall()

    if request.method == 'POST':
        raw_data = request.form['questions']
        try:
            parsed_data = parse_questions(raw_data)
            update_database(parsed_data, assignment_id, cur)
            conn.commit()
            message = "Изменения успешно сохранены."
        except Exception as e:
            conn.rollback()
            message = f"Ошибка: {str(e)}"

        cur.close()
        return render_template('edit_assignment.html', assignment_id=assignment_id, raw_data=raw_data, message=message)

    raw_data = format_questions(questions)
    cur.close()

    return render_template('edit_assignment.html', assignment_id=assignment_id, raw_data=raw_data)

def parse_questions(raw_data):
    parsed_data = []
    lines = raw_data.strip().split('\n')

    for line in lines:
        line = line.strip()

        if not line:
            continue 

        parts = line.split('|')
        
        if len(parts) < 4:
            raise ValueError(f"Ошибка парсинга строки: {line}")

        right_indexes = list(map(int, parts[0].split(',')))
        correct_answer_text = parts[1]
        question_text = parts[2]
        answers = parts[3:]

        parsed_data.append(
            {
            'right_indexes': right_indexes,
            'correct_answer_text': correct_answer_text,
            'question_text': question_text,
            'answers': answers,
        })

    return parsed_data

def update_database(parsed_data, assignment_id, cur):
    cur.execute( "SELECT * FROM questions WHERE assignment_id = %s", (assignment_id,))
    questions = cur.fetchall()

    questions = {q['question_text']: q for q in questions}
    parsed_data_dict = {item['question_text']: item for item in parsed_data}

    for question in questions:
        if question not in parsed_data_dict:
            cur.execute("DELETE FROM questions WHERE id = %s", (questions[question]['id'],))
            cur.execute("DELETE FROM answers WHERE question_id = %s", (questions[question]['id'],))

    for item in parsed_data:
        question = questions.get(item['question_text'], None)

        if question:
            question_id = question['id']
            cur.execute("UPDATE questions SET correct_answer_text = %s WHERE id = %s",(item['correct_answer_text'], question_id))

            cur.execute("DELETE FROM answers WHERE question_id = %s", (question_id,))
        else:
            cur.execute(
                """INSERT INTO questions (assignment_id, question_text, correct_answer_text) 
                VALUES (%s, %s, %s) RETURNING id""",
                (assignment_id, item['question_text'], item['correct_answer_text'])
            )
            question_id = cur.fetchone()['id']

        for index, answer_text in enumerate(item['answers']):

            status = 'правильный' if index in item['right_indexes'] else 'неправильный'
            cur.execute("INSERT INTO answers (question_id, answer_text, status) VALUES (%s, %s, %s)",(question_id, answer_text, status))


def format_questions(questions):
    lines = []
    for question in questions:
        right_indexes = ','.join(str(index) for index, status in enumerate(question['answer_statuses']) if status == 1)
        line = '|'.join([right_indexes, question['correct_answer_text'], question['question_text']] + question['answers'])
        lines.append(line)
    return '\n'.join(lines)

def format_questions(questions):
    lines = []
    for question in questions:
        correct_answers = [answer for index, answer in enumerate(question['answers']) if question['answer_statuses'][index] == 1]
        incorrect_answers = [answer for index, answer in enumerate(question['answers']) if question['answer_statuses'][index] == 0]
        
        answers = correct_answers + incorrect_answers

        right_indexes = ','.join(str(index) for index in range(len(correct_answers)))

        line = '|'.join([right_indexes, question['correct_answer_text'], question['question_text']] + answers)
        
        lines.append(line.replace("\n", ""))

    return '\n'.join(lines)

# if __name__ == "__main__":
#     app.run(host='0.0.0.0', port=5000)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl_context=(r'/etc/ssl/flask/cloudflare.crt', r'/etc/ssl/flask/cloudflare.key'))
