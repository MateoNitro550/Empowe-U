#!/usr/bin/python3

import os
import secrets
import mysql.connector
from openai import OpenAI
from passlib.hash import sha256_crypt
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)

secret_key = secrets.token_hex(16)
app.secret_key = secret_key

db_config = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'user': os.environ.get('DB_USER', 'user'),
    'password': os.environ.get('DB_PASSWORD', 'password'),
    'database': os.environ.get('DB_NAME', 'database')
}

client = OpenAI(api_key='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')

questions = [
    {'id': 1, 'category': 'Weight', 'text': '¿Cómo te sientes con tu peso actual?', 'options': ['Muy satisfecho/a', 'Satisfecho/a', 'Neutral', 'Insatisfecho/a', 'Muy insatisfecho/a'], 'value_mapping': {'Muy satisfecho/a': 0, 'Satisfecho/a': 1, 'Neutral': 2, 'Insatisfecho/a': 3, 'Muy insatisfecho/a': 4}},
    {'id': 2, 'category': 'Weight', 'text': '¿Con qué frecuencia te preocupas por tu apariencia física?', 'options': ['Nunca', 'Ocasionalmente', 'A menudo', 'Frecuentemente', 'Siempre'], 'value_mapping': {'Nunca': 0, 'Ocasionalmente': 1, 'A menudo': 2, 'Frecuentemente': 3, 'Siempre': 4}},
    {'id': 3, 'category': 'Weight', 'text': '¿Cómo te sientes acerca de tu apariencia física en comparación con tus pares?', 'options': ['Más que satisfecho/a', 'Satisfecho/a', 'Neutral', 'Insatisfecho/a', 'Muy insatisfecho/a'], 'value_mapping': {'Más que satisfecho/a': 0, 'Satisfecho/a': 1, 'Neutral': 2, 'Insatisfecho/a': 3, 'Muy insatisfecho/a': 4}},
    {'id': 4, 'category': 'Weight', 'text': '¿Has experimentado comentarios negativos sobre tu cuerpo?', 'options': ['Nunca', 'Ocasionalmente', 'A veces', 'Frecuentemente', 'Siempre'], 'value_mapping': {'Nunca': 0, 'Ocasionalmente': 1, 'A veces': 2, 'Frecuentemente': 3, 'Siempre': 4}},
    {'id': 5, 'category': 'Academic Pressure', 'text': '¿Cómo describirías el nivel de presión que sientes en tus estudios?', 'options': ['Muy bajo', 'Bajo', 'Moderado', 'Alto', 'Muy alto'], 'value_mapping': {'Muy bajo': 0, 'Bajo': 1, 'Moderado': 2, 'Alto': 3, 'Muy alto': 4}},
    {'id': 6, 'category': 'Academic Pressure', 'text': '¿Cuánto te afecta el estrés académico en tu vida diaria?', 'options': ['No afecta', 'Levemente afecta', 'Moderadamente afecta', 'Bastante afecta', 'Muy afecta'], 'value_mapping': {'No afecta': 0, 'Levemente afecta': 1, 'Moderadamente afecta': 2, 'Bastante afecta': 3, 'Muy afecta': 4}},
    {'id': 7, 'category': 'Academic Pressure', 'text': '¿Sientes presión para tomar decisiones importantes sobre tu futuro?', 'options': ['No', 'Un poco', 'Moderadamente', 'Bastante', 'Mucho'], 'value_mapping': {'No': 0, 'Un poco': 1, 'Moderadamente': 2, 'Bastante': 3, 'Mucho': 4}},
    {'id': 8, 'category': 'Academic Pressure', 'text': '¿Te sientes presionado/a por las expectativas de los demás en cuanto a tu rendimiento personal?', 'options': ['No', 'Poco', 'Moderadamente', 'Bastante', 'Mucho'], 'value_mapping': {'No': 0, 'Poco': 1, 'Moderadamente': 2, 'Bastante': 3, 'Mucho': 4}},
    {'id': 9, 'category': 'Emotional Health', 'text': '¿Cómo describirías tu estado de ánimo general?', 'options': ['Muy positivo', 'Positivo', 'Neutral', 'Negativo', 'Muy negativo'], 'value_mapping': {'Muy positivo': 0, 'Positivo': 1, 'Neutral': 2, 'Negativo': 3, 'Muy negativo': 4}},
    {'id': 10, 'category': 'Emotional Health', 'text': '¿Con qué frecuencia experimentas síntomas de ansiedad o tristeza?', 'options': ['Nunca', 'Ocasionalmente', 'A veces', 'Frecuentemente', 'Siempre'], 'value_mapping': {'Nunca': 0, 'Ocasionalmente': 1, 'A veces': 2, 'Frecuentemente': 3, 'Siempre': 4}},
    {'id': 11, 'category': 'Emotional Health', 'text': '¿Te sientes cómodo/a expresando tus emociones con amigos o familiares?', 'options': ['Muy cómodo/a', 'Cómodo/a', 'Neutral', 'Incómodo/a', 'Muy incómodo/a'], 'value_mapping': {'Muy cómodo/a': 0, 'Cómodo/a': 1, 'Neutral': 2, 'Incómodo/a': 3, 'Muy incómodo/a': 4}},
    {'id': 12, 'category': 'Emotional Health', 'text': '¿Cómo manejas el estrés en tu vida diaria?', 'options': ['Estrategias efectivas', 'Estrategias moderadamente efectivas', 'Estrategias poco efectivas', 'Sin estrategias definidas', 'No manejo el estrés'], 'value_mapping': {'Estrategias efectivas': 0, 'Estrategias moderadamente efectivas': 1, 'Estrategias poco efectivas': 2, 'Sin estrategias definidas': 3, 'No manejo el estrés': 4}},
    {'id': 13, 'category': 'Interpersonal Relationships', 'text': '¿Sientes presión social para encajar con ciertos grupos?', 'options': ['Nada de presión', 'Poca presión', 'Moderada', 'Alta presión', 'Muy alta presión'], 'value_mapping': {'Nada de presión': 0, 'Poca presión': 1, 'Moderada': 2, 'Alta presión': 3, 'Muy alta presión': 4}},
    {'id': 14, 'category': 'Interpersonal Relationships', 'text': '¿Tienes personas en las que confías para hablar sobre tus inseguridades?', 'options': ['Sí, varias personas', 'Sí, una o dos personas', 'No estoy seguro/a', 'No, pero me gustaría tener alguien', 'No, prefiero no compartir'], 'value_mapping': {'Sí, varias personas': 0, 'Sí, una o dos personas': 1, 'No estoy seguro/a': 2, 'No, pero me gustaría tener alguien': 3, 'No, prefiero no compartir': 4}},
    {'id': 15, 'category': 'Interpersonal Relationships', 'text': '¿Tienes dificultades para hacer amigos o sentirte aceptado/a en grupos sociales?', 'options': ['No', 'Ocasionalmente', 'A veces', 'Frecuentemente', 'Siempre'], 'value_mapping': {'No': 0, 'Ocasionalmente': 1, 'A veces': 2, 'Frecuentemente': 3, 'Siempre': 4}},
    {'id': 16, 'category': 'Interpersonal Relationships', 'text': '¿Cómo te afecta la soledad en tu bienestar emocional?', 'options': ['No me afecta', 'Levemente afecta', 'Moderadamente afecta', 'Bastante afecta', 'Muy afecta'], 'value_mapping': {'No me afecta': 0, 'Levemente afecta': 1, 'Moderadamente afecta': 2, 'Bastante afecta': 3, 'Muy afecta': 4}},
]

def execute_query(query, params=None, operation="select"):
    # Connect to the database
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

         # Check the operation type
        if operation.lower() == "select":
            # Fetch the data
            data = cursor.fetchall()
            conn.close()
            return data
        else:
            # For other operations ('update', 'insert', 'delete'), commit changes
            conn.commit()
            conn.close()
            return True

    except Exception as e:
        conn.close()
        return str(e)

def hash_password(password):
    return sha256_crypt.hash(password)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        input_username = request.form['username']
        input_password = request.form['password']

        check_user_query = "SELECT id, username, password, questionnaire FROM users WHERE username = %s"
        user_data = execute_query(check_user_query, (input_username,))

        if user_data:
            user_id, stored_username, stored_password, questionnaire = user_data[0]

            if sha256_crypt.verify(input_password, stored_password):
                if not questionnaire:
                    session['logged_in'] = True
                    session['username'] = input_username
                    return redirect(url_for('questionnaire'))

                session['logged_in'] = True
                return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error_message = None

    if request.method == 'POST':
        input_username = request.form['username']
        input_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if input_password != confirm_password:
            error_message = "Las contraseñas no coinciden"

        else:
            check_username_query = "SELECT id FROM users WHERE username = %s"
            existing_user = execute_query(check_username_query, (input_username,))

            if existing_user:
                error_message = "El nombre de usuario ya existe. Por favor, elige otro."

            else:
                hashed_password = hash_password(input_password)

                insert_user_query = "INSERT INTO users (username, password, questionnaire) VALUES (%s, %s, %s)"
                execute_query(insert_user_query, (input_username, hashed_password, 0), operation="insert")

                return redirect(url_for('login'))

    return render_template('register.html', error=error_message)

@app.route('/questionnaire', methods=['GET', 'POST'])
def questionnaire():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        results = {}
        for question in questions:
            answer = request.form.get(f'answer_{question["id"]}')
            if answer:
                category = question['category']
                value = question['value_mapping'][answer]
                results[category] = results.get(category, 0) + value

        highest_insecurity_categories = []
        max_score = max(results.values())

        for category, score in results.items():
            if score == max_score:
                highest_insecurity_categories.append(category)

        if max_score == 0:
            highest_insecurity_categories = []

        """
        return jsonify({
            'final_results': results,
            'highest_insecurity_categories': highest_insecurity_categories
        })
        """

        input_username = session.get('username')
        update_questionnaire_query = "UPDATE users SET questionnaire = 1 WHERE username = %s"
        update_insecurity_query = "UPDATE users SET insecurity = %s WHERE username = %s"
        execute_query(update_questionnaire_query, (input_username,), operation="update")

        highest_insecurity_categories_str = ', '.join(highest_insecurity_categories)

        if len(highest_insecurity_categories) == 1:
            highest_insecurity_categories_str = highest_insecurity_categories[0]

        execute_query(update_insecurity_query, (highest_insecurity_categories_str, input_username), operation="update")

        return redirect(url_for('dashboard'))


    return render_template('questionnaire.html', questions=questions)

@app.route('/tips')
def tips():
    return render_template('tips.html')

@app.route('/ai', methods=['GET', 'POST'])
def ai():
    if request.method == 'POST':
        user_message = request.form['user_message']
        ai_response = generate_ai_response(user_message)
        return jsonify({'ai_response': ai_response})

    return render_template('ai.html')

def generate_ai_response(user_message):
    system_message = "Necesito que actúes como un amigo, sin decirme que vas a actuar como tal. La persona con la que vas a hablar tiene una inseguridad en su peso. Debes hacerle sentir en un lugar seguro y confiada de la información que te está proporcionando. Utiliza un lenguaje natural de amigos, nada forzado. Pero que las respuestas no sean excesivamente largas, recuerda que esto es un chat."

    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message},
    ]

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=messages,
        temperature=1,
        max_tokens=256,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )

    response_message = response.choices[0].message.content
    return response_message

@app.route('/experts')
def experts():
    return render_template('experts.html')

@app.route('/community')
def community():
    return render_template('community.html')

@app.route('/logout')
def logout():
    session.clear()
    if 'timeout' in request.args:
        return render_template('timeout.html')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
