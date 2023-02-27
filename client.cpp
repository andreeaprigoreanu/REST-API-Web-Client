#include <stdio.h>          /* printf, sprintf */
#include <stdlib.h>         /* exit, atoi, malloc, free */
#include <unistd.h>         /* read, write, close */
#include <string.h>         /* memcpy, memset */
#include <sys/socket.h>     /* socket, connect */
#include <netinet/in.h>     /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>          /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include <iostream>
#include <bits/stdc++.h>
#include <nlohmann/json.hpp>    /* used to parse json files */

#include "helpers.h"
#include "requests.h"

using namespace std;
using json = nlohmann::json;

#define IP "34.241.4.235"   // server ip
#define PORT 8080           // server port
#define COMMAND_SIZE 100
#define MAX_INPUT_SIZE 100

// function that reads username and password
char *get_client_credentials() {
    string username, password;

    // read username
    cout << "username=";
    cin >> username;
    cin.ignore();
    // read password
    cout << "password=";
    cin >> password;
    cin.ignore();

    // create json object with username and password
    json credentials_json = {{"username", username}, {"password", password}};
    string credentials_str = credentials_json.dump();

    // convert string to char
    char *credentials = (char *)malloc(credentials_str.size() + 1);
    strcpy(credentials, credentials_str.c_str());

    return credentials;
}

// function that reads book details
char *get_new_book() {
    char buffer[MAX_INPUT_SIZE];

    // get client input
    cout << "title=";
    fgets(buffer, MAX_INPUT_SIZE, stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    string title(buffer);

    cout << "author=";
    fgets(buffer, MAX_INPUT_SIZE, stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    string author(buffer);

    cout << "genre=";
    fgets(buffer, MAX_INPUT_SIZE, stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    string genre(buffer);

    cout << "publisher=";
    fgets(buffer, MAX_INPUT_SIZE, stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    string publisher(buffer);

    cout << "page_count=";
    fgets(buffer, MAX_INPUT_SIZE, stdin);
    buffer[strcspn(buffer, "\n")] = 0;
    string page_count(buffer);

    json book_json = {{"title", title}, {"author", author}, {"genre", genre},
                        {"publisher", publisher}, {"page_count", page_count}};
    string book_str = book_json.dump();

    char *book_details = (char *)calloc(book_str.size() + 1, sizeof(char));
    strcpy(book_details, book_str.c_str());

    return book_details;
}

// function that extracts session cookie from server response to login command
string extract_session_cookie(string response) {
    string token;
    istringstream response_stream(response);

    while (getline(response_stream, token, ' ')) {
        if (token.compare(0, 7, "connect") == 0) {
            break;
        }
    }

    return token;
}

// function that extracts jwt token from server response to
// enter_library command
string extract_jwt_token(string response) {
    string jwt_token;
    istringstream response_stream(response);

    while (getline(response_stream, jwt_token, '\n')) {
        if (jwt_token.compare(0, 9, "{\"token\":") == 0) {
            break;
        }
    }

    return jwt_token.substr(10, jwt_token.size() - 12);
}

string extract_book_response(string response) {
    string details;
    istringstream response_stream(response);

    while (getline(response_stream, details, '\n')) {
        if (details.compare(0, 9, "[{") == 0) {
            break;
        }
    }

    return details;
}

// function that contains the steps to register in a client
string register_client(int sockfd) {
    char *client_credentials = get_client_credentials();
    char **login_data = (char **)calloc(1, sizeof(char *));
    login_data[0] = (char *)calloc(strlen(client_credentials) + 1, sizeof(char));
    strcpy(login_data[0], client_credentials);

    // create post message
    char *message = compute_post_request(IP, "/api/v1/tema/auth/register", "application/json", login_data, 1, NULL, 0, false);
    // send post request to server
    send_to_server(sockfd, message);
    // get response from server
    char *response = receive_from_server(sockfd);

    if (strstr(response, "error") != NULL) {
        free(login_data[0]);
        free(login_data);
        free(message);

        return "";
    }

    free(login_data[0]);
    free(login_data);
    free(message);

    string response_str(response);
    return response_str;
}

// function that contains the steps to log in a client
string login_client(int sockfd) {
    char *client_credentials = get_client_credentials();
    char **login_data = (char **)calloc(1, sizeof(char *));
    login_data[0] = (char *)calloc(strlen(client_credentials) + 1, sizeof(char));
    strcpy(login_data[0], client_credentials);

    // create post message
    char *message = compute_post_request(IP, "/api/v1/tema/auth/login", "application/json", login_data, 1, NULL, 0, false);
    // send post request to server
    send_to_server(sockfd, message);
    // get response from server
    char *response = receive_from_server(sockfd);

    if (strstr(response, "error") != NULL) {
        free(login_data[0]);
        free(login_data);
        free(message);

        return "";
    }

    free(login_data[0]);
    free(login_data);
    free(message);

    string response_str(response);
    return response_str;
}

// function that contains the steps to get library access
string get_library_access(char *url, int sockfd, string cookie) {
    char **cookie_chr = (char **)calloc(1, sizeof(char *));
    cookie_chr[0] = (char *) calloc(1, cookie.size() + 1);
    strcpy(cookie_chr[0], cookie.c_str());

    // create get message
    char *message = compute_get_request(IP, url, NULL, cookie_chr, 1, false);
    // send get request to server
    send_to_server(sockfd, message);
    // get response from server
    char* response = receive_from_server(sockfd);
    if (strstr(response, "error") != NULL) {
        free(cookie_chr[0]);
        free(cookie_chr);
        free(message);

        return "";
    }


    free(cookie_chr[0]);
    free(cookie_chr);
    free(message);

    string response_str(response);
    return response_str;
}

// function that contains the steps to get all books
string access_books(char *url, int sockfd, string cookie, string auth_header) {
    char **header_and_cookie = (char **)calloc(2, sizeof(char *));
    header_and_cookie[0] = (char *) calloc(1, auth_header.size() + 1);
    strcpy(header_and_cookie[0], auth_header.c_str());
    header_and_cookie[1] = (char *) calloc(1, cookie.size() + 1);
    strcpy(header_and_cookie[1], cookie.c_str());

    // create get message
    char *message = compute_get_request(IP, url, NULL, header_and_cookie, 2, true);
    // send get request to server
    send_to_server(sockfd, message);
    // get response from server
    char* response = receive_from_server(sockfd);
    if (strstr(response, "error") != NULL) {
        free(header_and_cookie[0]);
        free(header_and_cookie);
        free(message);

        return "";
    }


    free(header_and_cookie[0]);
    free(header_and_cookie[1]);
    free(header_and_cookie);
    free(message);

    string response_str(response);
    return response_str;  
}

// function that contains the steps to get book with given id
string add_book(char *url, int sockfd, string cookie, string auth_header) {
    // get book details from user
    char *book_details_from_client = get_new_book();
    char **book_details = (char **)calloc(1, sizeof(char *));
    book_details[0] = (char *)calloc(strlen(book_details_from_client) + 1, sizeof(char));
    strcpy(book_details[0], book_details_from_client);

    // add header and cookie
    char **header_and_cookie = (char **)calloc(2, sizeof(char *));
    header_and_cookie[0] = (char *) calloc(1, auth_header.size() + 1);
    strcpy(header_and_cookie[0], auth_header.c_str());
    header_and_cookie[1] = (char *) calloc(1, cookie.size() + 1);
    strcpy(header_and_cookie[1], cookie.c_str());

    // create message to post book
    char *message = compute_post_request(IP, url, "application/json", book_details, 1, header_and_cookie, 2, true);
    // send post request to server
    send_to_server(sockfd, message);
    // get response from server
    char *response = receive_from_server(sockfd);
    if (strstr(response, "error") != NULL) {
        free(book_details[0]);
        free(book_details);
        free(header_and_cookie[0]);
        free(header_and_cookie[1]);
        free(header_and_cookie);
        return "";
    }

    free(book_details[0]);
    free(book_details);
    free(header_and_cookie[0]);
    free(header_and_cookie[1]);
    free(header_and_cookie);

    string response_str(response);
    return response_str;
}

// function that contains the steps to delete book with given id
string delete_book(char *url, int sockfd, string cookie, string auth_header) {
    char **header_and_cookie = (char **)calloc(2, sizeof(char *));
    header_and_cookie[0] = (char *) calloc(1, auth_header.size() + 1);
    strcpy(header_and_cookie[0], auth_header.c_str());
    header_and_cookie[1] = (char *) calloc(1, cookie.size() + 1);
    strcpy(header_and_cookie[1], cookie.c_str());

    // create message to delete book
    char* message = compute_delete_request(IP, url, NULL, header_and_cookie, 2, true);
    // send delete request to server
    send_to_server(sockfd, message);
    // get response from server
    char* response = receive_from_server(sockfd);
    if (strstr(response, "error") != NULL) {
        free(header_and_cookie[0]);
        free(header_and_cookie[1]);
        free(header_and_cookie);
        return "";
    }

    free(header_and_cookie[0]);
    free(header_and_cookie[1]);
    free(header_and_cookie);
    free(message);

    string response_str(response);
    return response_str;
}

// function that contains the steps to log out client
string logout_client(int sockfd, string cookie) {
    char **cookie_to_be_send = (char **)calloc(1, sizeof(char *));
    cookie_to_be_send[0] = (char *)calloc(cookie.size() + 1, sizeof(char));
    strcpy(cookie_to_be_send[0], cookie.c_str());

    // create message to end session
    char *message = compute_delete_request(IP, "/api/v1/auth/logout", NULL, cookie_to_be_send, 1, false);
    // send delete request to server
    send_to_server(sockfd, message);
    // get server response
    char* response = receive_from_server(sockfd);
    if (strstr(response, "error") != NULL) {
        free(cookie_to_be_send[0]);
        free(cookie_to_be_send[1]);
        free(cookie_to_be_send);
        free(message);
        return "";
    }

    free(cookie_to_be_send[0]);
    free(cookie_to_be_send[1]);
    free(cookie_to_be_send);
    free(message);

    string response_str(response);
    return response_str;
}

int main(int argc, char *argv[])
{
    string message;
    string response;
    int sockfd;
    bool logged_in = false, library_access = false;
    string cookie, library_jwt;

    while (1) {
        // connect to server
        sockfd = open_connection(IP, PORT, AF_INET, SOCK_STREAM, 0);
        DIE(sockfd < 0, "connection failed\n");

        // read user command
        char command[COMMAND_SIZE];
        fgets(command, COMMAND_SIZE, stdin);

        if (strncmp(command, "register", 8) == 0) {
            if (logged_in) {
                // client is not logged in
                cout << "Log out before register" << endl << endl;
                close_connection(sockfd);
                continue;
            }
            response = register_client(sockfd);
            if (response.compare("") == 0) {
                cout << "Username taken!" << endl << endl;
                close_connection(sockfd);
                continue;
            }

            // successfull registration
            cout << "Registered successfully" << endl;
            cout << "Server response:" << endl;
            cout << response << endl << endl;

            close_connection(sockfd);
            continue;
        }

        if (strncmp(command, "login", 5) == 0) {
            if (logged_in) {
                // client is not logged in
                cout << "Already logged in" << endl << endl;
                close_connection(sockfd);
                continue;
            }
            
            response = login_client(sockfd);

            if (response.compare("") == 0) {
                cout << "Invalid credentials" << endl << endl;
                close_connection(sockfd);
                continue;
            }

            // successfull registration
            logged_in = true;
            cout << "Logged in" << endl;
            cout << "Server response:" << endl;
            cout << response << endl << endl;

            // extract cookie
            cookie = extract_session_cookie(response);

            close_connection(sockfd);
            continue;
        }

        if (strncmp(command, "enter_library", 13) == 0) {
            if (!logged_in) {
                // client is not logged in
                cout << "You have to be logged in" << endl << endl;
                close_connection(sockfd);
                continue;
            }
            // get cookie response

            response = get_library_access("/api/v1/tema/library/access", sockfd, cookie);

            if (response.compare("") == 0) {
                cout << "Error" << endl << endl;
                close_connection(sockfd);
                continue;
            }

            cout << "Access granted" << endl;
            library_access = true;
            library_jwt = extract_jwt_token(response);
            cout << "Access token: " << library_jwt << endl << endl;

            close_connection(sockfd);
            continue;
        }

        if (strncmp(command, "get_books", 9) == 0) {
            if (!logged_in) {
                cout << "You have to be logged in" << endl << endl;
                close_connection(sockfd);
                continue;
            }

            if (!library_access) {
                cout << "No access to library" << endl << endl;
                close_connection(sockfd);
                continue;
            }

            string authorization = "Authorization: Bearer " + library_jwt;
            response = access_books("/api/v1/tema/library/books", sockfd, cookie, authorization);
            if (response.compare("") == 0) {
                cout << "Error" << endl << endl;
                close_connection(sockfd);
                continue;
            }
            cout << "Server response:" << endl;
            cout << extract_book_response(response) << endl << endl;

            close_connection(sockfd);
            continue;
        }

        if (strncmp(command, "get_book", 8) == 0) {
            if (!logged_in) {
                // client is not logged in
                cout << "You have to be logged in" << endl << endl;
                close_connection(sockfd);
                continue;
            }
            if (!library_access) {
                cout << "No access to library" << endl << endl;
                close_connection(sockfd);
                continue;
            }

            string id;
            cout << "id=";
            cin >> id;
            cin.ignore();

            // create url for requested book
            string url_str = "/api/v1/tema/library/books/" + id;
            char *url = (char *)calloc(url_str.size() + 1, sizeof(char));
            strcpy(url, url_str.c_str());

            // create authorization header
            string authorization = "Authorization: Bearer " + library_jwt;

            response = access_books(url, sockfd, cookie, authorization);
            if (response.compare("") == 0) {
                cout << "Invalid book ID" << endl << endl;
                free(url);
                close_connection(sockfd);
                continue;
            }

            cout << "Server response:" << endl;
            cout << extract_book_response(response) << endl << endl;

            free(url);
            close_connection(sockfd);
            continue;
        }

        if (strncmp(command, "add_book", 8) == 0) {
            if (!logged_in) {
                // client is not logged in
                cout << "You have to be logged in" << endl << endl;
                close_connection(sockfd);
                continue;
            }
            if (!library_access) {
                cout << "No access to library" << endl << endl;
                close_connection(sockfd);
                continue;
            }

            string authorization = "Authorization: Bearer " + library_jwt;
            response = add_book("/api/v1/tema/library/books", sockfd, cookie, authorization);
            if (response.compare("") == 0) {
                cout << "Invalid book details format" << endl << endl;
                close_connection(sockfd);
                continue;
            }

            cout << "Server response:" << endl;
            cout << response << endl << endl;

            close_connection(sockfd);
            continue;
        }

        if (strncmp(command, "delete_book", 11) == 0) {
            if (!logged_in) {
                // client is not logged in
                cout << "You have to be logged in" << endl << endl;
                close_connection(sockfd);
                continue;
            }
            if (!library_access) {
                cout << "No access to library" << endl << endl;
                close_connection(sockfd);
                continue;
            }

            // get user input
            string id;
            cout << "id=";
            cin >> id;
            cin.ignore();

            string url_str = "/api/v1/tema/library/books/" + id;
            char* url = (char *) calloc(url_str.size() + 1, sizeof(char));
            strcpy(url, url_str.c_str());

            string authorization = "Authorization: Bearer " + library_jwt;
            response = delete_book(url, sockfd, cookie, authorization);
            if (response.compare("") == 0) {
                cout << "Invalid book id" << endl << endl;
                close_connection(sockfd);
                continue;
            }

            cout << "Server response:" << endl;
            cout << response << endl << endl;
            free(url);

            close_connection(sockfd);
            continue;
        }

        if (strncmp(command, "logout", 6) == 0) {
            if (!logged_in) {
                // client is not logged in
                cout << "You have to be logged in" << endl;
                close_connection(sockfd);
                continue;
            }

            response = logout_client(sockfd, cookie);
            if (response.compare("") == 0) {
                cout << "Error" << endl;
                close_connection(sockfd);
                continue;
            }

            cookie = "";
            library_jwt = "";
            logged_in = false;
            library_access = false;
            cout << "Logged out" << endl << endl;

            close_connection(sockfd);
            continue;
        }

        if (strncmp(command, "exit", 4) == 0) {
            close_connection(sockfd);
            break;
        }

        cout << "Invalid command" << endl;
        cout << "Possible commands: register, login, enter_library, get_books, get_book, add_book, delete_book, logout, exit" << endl;
    }

    return 0;
}
