from flask import Flask, render_template, request, redirect
import requests
import re
import textwrap
import openai
import json
from langchain import OpenAI
from langchain.document_loaders.csv_loader import CSVLoader
import sys
from dotenv import load_dotenv
import csv
import os
import time
from flask import jsonify




app = Flask(__name__)

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")
filepath = os.getenv("CSV_PATH")

rules = """
the above is the user manual input.
this is a chatbot of a security operation center.
as the response will be used for a program, please follow the below rules in your response like a programming if-else instruction:
- (if you think the user input is querying security operation center+a particular ticket on the ticketing systemplease explain why you think so then respond in a json with two fields one field is "redirect": "ticketing system", another field is "ticket_number", then extract the ticket number in user input for me, otherwise ignore this)
- (else, if you think the user input is related to security operation center+overall tickets on the ticketing system, please explain why you think so then respond in a json with two fields one field is "redirect": "ticketing trends", another field is "trend", then extract the meaning in user input for me, otherwise ignore this)
- (otherwise just reply normally)
"""

def search_ticket(ticket_number, current_time_milliseconds):
    #print(f"Searching ticket: {ticket_number}")

    stdout_original = sys.stdout
    
    loader = CSVLoader(filepath)
    data = loader.load()

    llm = OpenAI(temperature=0)

    from langchain.agents import create_csv_agent
    agent = create_csv_agent(llm, filepath, verbose=True)

    with open('output.txt', 'w') as f:
        sys.stdout = f
        response = agent.run(f"search the ticket with Issue Key {ticket_number}, output to {current_time_milliseconds}.txt")
        sys.stdout = stdout_original


def create_temp_file(file_path, content):
    with open(file_path, 'w') as file:
        file.write(content)

def search_ticket_in_csv(ticket_number, current_time_milliseconds):
    
    temp_file = f"{current_time_milliseconds}.txt"

    if os.path.exists(temp_file):
        os.remove(temp_file)
        create_temp_file(f'{current_time_milliseconds}.txt', 'This is the content of the temp file.')


    with open(filepath, "r") as csv_file:
        reader = csv.reader(csv_file)
        headers = next(reader)  # Read the header row
        found_row = None

        for row in reader:
            issue_key = row[headers.index("Issue key")]
            if issue_key == ticket_number:
                found_row = row
                break

    if found_row:
        with open(temp_file, "w") as output_file:
            writer = csv.writer(output_file)
            writer.writerow(headers)
            writer.writerow(found_row)
    else:
        print("Ticket not found.")

def search_ticket2(ticket_number, current_time_milliseconds):
    #print(f"Searching ticket: {ticket_number}")

    stdout_original = sys.stdout
    
    loader = CSVLoader(filepath)
    data = loader.load()

    llm = OpenAI(temperature=0)

    from langchain.agents import create_csv_agent
    agent = create_csv_agent(llm, filepath, verbose=True)

    with open('output.txt', 'w') as f:
        sys.stdout = f
        response = agent.run(f"{ticket_number}, output to {current_time_milliseconds}.txt")
        sys.stdout = stdout_original

def read_csv_file(file_path):
    data = []
    columns = []

    with open(file_path, 'r') as file:
        csv_reader = csv.DictReader(file)
        columns = csv_reader.fieldnames
        data = list(csv_reader)
        
        # for row in data:
        #     print('row:', str(row))  # Convert row to a string representation

    return columns, data

loaded = False  # Flag to track if the page has been loaded

@app.route('/', methods=['GET', 'POST'])
def index():
    global loaded

    if request.method == 'POST' and 'input_text' in request.form:
        user_input = request.form['input_text']
        instruction = request.form['input_text2']
        output = callgpt(user_input, instruction)
        # return render_template('index.html', output=output)
        return output
    else:
        print('loading csv...')
        if not loaded:
            print('not loaded csv...')
            filepath = os.getenv("CSV_PATH")
            columns, data = read_csv_file(filepath)
            loaded = False
            # loaded = True
        else:
            columns = []
            data = []

        return render_template('tab2.html', columns=columns, data=data)

def callgpt(input_text, instruction):

    current_time_milliseconds = int(time.time() * 1000)
    print(current_time_milliseconds)
    start_time = time.time()
    print("Start Time:", start_time)
    conversation = []
    conversation2 = []
    ai_response2 = ""
    user_input = input_text

    conversation.append({"role": "user", "content": user_input})
    conversation.append({"role": "assistant", "content": rules})

    # response = openai.ChatCompletion.create(
    #     model='gpt-3.5-turbo',
    #     messages=conversation
    # )

    # ai_response = response.choices[0].message.content
    ai_response = f"""
    {{
        "type": "ticketing system",
        "ticket_number": "{input_text.strip()}"
    }}
    """

    print("airesponse: " + ai_response)

    if "ticketing system" in ai_response.lower():
        print("OK")
        try:
            start_index = ai_response.find("{")
            end_index = ai_response.rfind("}") + 1

            json_data = ai_response[start_index:end_index]
            response_json = json.loads(json_data)
            ticket_number = response_json.get("ticket_number")
            search_ticket_in_csv(ticket_number, current_time_milliseconds)
            print("after search ticket in csv")
            # conversation.append({"role": "assistant", "content": ai_response})

            tempfilename = f"{current_time_milliseconds}.txt"
            with open(tempfilename, "r") as file:
                content = file.read()

            # user_input2 = f"""
            # based on this jira ticket output for my security operation center
            # the output txt: {content}
            # can you help me to 
            # 1. turn this jira ticket into a report
            # 2. also help me to determine whether this is false positive
            # 3. summarize the description for me, within 300 words
            # 4. no need show the raw log, but beautify and interpret the log for me
            # 5. based on the log, please suggest how to investigate and resolve
            # 6. put the investigation at the end after a long line -------
            # 7. based on the log please also suggest a MITRE ATTACK path
            # 8. write me a wazuh XML rule to whitelist this
            # 9. help me draft a client email reporting the problem
            # """
            user_input2 = f"""
            based on this jira ticket output for my security operation center
            the output txt: {content}
            can you help me to do the below. respond listed in numbered point form, repeat my question first in each point, then answer (inside each answer dont use any numbered points)in the next line:
            {instruction}
            """
            conversation2 = []
            conversation2.append({"role": "user", "content": user_input2})

            response2 = openai.ChatCompletion.create(
                model='gpt-3.5-turbo',
                messages=conversation2
            )

            ai_response2 = response2.choices[0].message.content
            #print("--------------------------------------------")
            #print("Chatbot:", ai_response2)

            if os.path.exists(tempfilename):
                os.remove(tempfilename)
                print(f"{tempfilename} File removed successfully.")
            else:
                print(f"{tempfilename} File does not exist.")
        except ValueError:
            print("Invalid JSON format in AI response.")
    elif "ticketing system" in ai_response.lower():
        #print("Else")
        search_ticket2(user_input)


    # Print the timestamp after the function
    end_time = time.time()
    print("End Time:", end_time)

    # Calculate the elapsed time
    elapsed_time = end_time - start_time
    print("Elapsed Time:", elapsed_time)

    output = ai_response2
    output = textwrap.dedent(output).strip()

    # bullet_points = re.split(r"(?<=\n)\s(?=\d+\.\s)", output)
    bullet_points = re.split(r"(?<=\n|,)\s(?=\d+\.\s)", output)


    bullet_points_with_headers = []

    for bullet_point in bullet_points:
        lines = bullet_point.split("\n")
        header = lines[0].strip()
        content = "\n".join(lines[1:]).strip()
        content = textwrap.dedent(content).strip()
        bullet_points_with_headers.append((header, content))

    return bullet_points_with_headers

if __name__ == '__main__':
    app.run(port=3000)
