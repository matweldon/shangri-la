# Purpose

The goal of this project is to learn about implementing authentication, encryption and decryption in a static web application, 
and using Firestore as a no-SQL database with row-level access control.

# Shangri-la 

A simple, mobile-friendly static web app that allows users to store text-only secrets, encrypted in a backend database, 
and access them using a master password.

# Features

- Very simple interface: list of secrets; hamburger menu for settings; + button to add a secret; drag to reorder list
- Add a secret:
  - type secret and description
  - type password
  - save
- View a secret:
  - prompt for password;
  - success: show the secret with copy-to-clipboard button
  - failure: Incorrect password, try again
- Multiple users
- Password and Secrets are **never** stored in plaintext
- Master password is hashed and stored locally to give the user feedback that they have the right password
- Local mode where secrets are stored, encrypted, in local storage
- Online mode where secrets are stored, encrypted, in Firestore with access control

# Stretch features

- Authenticate using fingerprint (is this possible to implement on static app?)
- A feature to send a secret to another user with single-use password - uses Firestore
  - The user has to communicate the password via other means
- In-browser unit testing using Jasmine framework. A route accessible via hamburger menu to run all the tests in browser

# Constraints

- Uses Firestore, but you will not have any access to Firestore in developing the app.
- You will have to write Firestore functionality and ask me to test it.
- You can write mock functions that mimic the firestore but store the data in localStorage to mimic Firestore calls
