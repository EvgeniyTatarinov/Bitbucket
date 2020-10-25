1. #### Package installation:
    - sudo apt install postgresql
    - sudo apt install python3-pip
    - sudo apt-get build-dep python3-psycopg2

2. #### Database settings:
    - create database bitbucket;
    - create user [DATABASE_USERNAME] with encrypted password '[DATABASE_PASSWORD]';
    - grant all privileges on database bitbucket to [DATABASE_USERNAME];
    - Specify database settings in the file settings.py
    
3. #### Install packages from a file requirements.txt
    - pip3 install -r requirements.txt

4. #### To perform the migration
    - If there is no alembic folder in the project, you must install alembic with the command: "alembic init alembic"
        - In the alembic.ini file, change the parameter: sqlalchemy. url, specifying the necessary database settings
        - alembic revision -m "[unique_migration_name]"
    - alembic upgrade head
    
5. #### To start the project, run: python3 main.py
    
    
