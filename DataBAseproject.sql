-- =========================
-- RESET DATABASE
-- =========================

DROP DATABASE IF EXISTS skillcollab;
CREATE DATABASE skillcollab;

USE skillcollab;
ALTER TABLE project
    ADD COLUMN max_members INT NULL DEFAULT NULL;
 

 
ALTER TABLE notification
    ADD COLUMN notif_type VARCHAR(20) NOT NULL DEFAULT 'message',
    ADD COLUMN project_id INT NULL,
    ADD CONSTRAINT fk_notification_project
        FOREIGN KEY (project_id) REFERENCES project(project_id)
        ON DELETE CASCADE;
        
CREATE TABLE user (
    user_id INT AUTO_INCREMENT PRIMARY KEY,

    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,

    bio TEXT,

    status VARCHAR(20) DEFAULT 'active',

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE skill (
    skill_id INT AUTO_INCREMENT PRIMARY KEY,

    skill_name VARCHAR(100) NOT NULL UNIQUE
);


CREATE TABLE user_skill (

    user_id INT,
    skill_id INT,

    level VARCHAR(20),

    PRIMARY KEY(user_id, skill_id),

    FOREIGN KEY(user_id)
        REFERENCES user(user_id)
        ON DELETE CASCADE,

    FOREIGN KEY(skill_id)
        REFERENCES skill(skill_id)
        ON DELETE CASCADE
);


CREATE TABLE project (

    project_id INT AUTO_INCREMENT PRIMARY KEY,

    project_name VARCHAR(150) NOT NULL,

    description TEXT,

    owner_id INT NOT NULL,

    status VARCHAR(20) DEFAULT 'active',

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(owner_id)
        REFERENCES user(user_id)
        ON DELETE CASCADE
);



CREATE TABLE project_skill (

    project_id INT,
    skill_id INT,

    PRIMARY KEY(project_id, skill_id),

    FOREIGN KEY(project_id)
        REFERENCES project(project_id)
        ON DELETE CASCADE,

    FOREIGN KEY(skill_id)
        REFERENCES skill(skill_id)
        ON DELETE CASCADE
);



CREATE TABLE application (

    application_id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NOT NULL,

    project_id INT NOT NULL,

    status ENUM(
        'pending',
        'accepted',
        'rejected'
    ) DEFAULT 'pending',

    note TEXT,

    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id)
        REFERENCES user(user_id)
        ON DELETE CASCADE,

    FOREIGN KEY(project_id)
        REFERENCES project(project_id)
        ON DELETE CASCADE
);


CREATE TABLE message (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    project_id INT NOT NULL,
    sender_id INT NOT NULL,
    content TEXT NOT NULL,
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read TINYINT DEFAULT 0,
    FOREIGN KEY (project_id)
        REFERENCES project (project_id)
        ON DELETE CASCADE,
    FOREIGN KEY (sender_id)
        REFERENCES user (user_id)
        ON DELETE CASCADE
);

CREATE TABLE notification (

    notification_id INT AUTO_INCREMENT PRIMARY KEY,

    user_id INT NOT NULL,

    message TEXT NOT NULL,

    is_read TINYINT DEFAULT 0,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY(user_id)
        REFERENCES user(user_id)
        ON DELETE CASCADE
);

CREATE TABLE project_comment (
    comment_id  INT          AUTO_INCREMENT PRIMARY KEY,
    project_id  INT          NOT NULL,
    user_id     INT          NOT NULL,
    content     TEXT         NOT NULL,
    created_at  DATETIME     DEFAULT NOW(),

    FOREIGN KEY (project_id) REFERENCES project(project_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)    REFERENCES user(user_id)       ON DELETE CASCADE
);


        
INSERT INTO skill (skill_name) VALUES

('Python'),
('Java'),
('C++'),
('C'),
('JavaScript'),
('TypeScript'),
('PHP'),
('C#'),
('Go'),
('Rust'),

('HTML'),
('CSS'),
('React'),
('Angular'),
('Vue.js'),
('Node.js'),
('Express.js'),
('Bootstrap'),

('MySQL'),
('PostgreSQL'),
('MongoDB'),
('SQLite'),

('Machine Learning'),
('Deep Learning'),
('Data Analysis'),
('Pandas'),
('NumPy'),
('TensorFlow'),
('PyTorch'),

('Android Development'),
('Flutter'),
('React Native'),

('Git'),
('GitHub'),
('Docker'),
('Kubernetes'),
('Linux'),

('AWS'),
('Azure'),
('Google Cloud'),

('Ethical Hacking'),
('Network Security'),
('Penetration Testing'),

('Problem Solving'),
('DSA'),
('OOP');
SELECT * FROM user;

ALTER TABLE user
ADD bio TEXT;


ALTER TABLE project
    ADD COLUMN max_members INT NULL DEFAULT NULL;
 

