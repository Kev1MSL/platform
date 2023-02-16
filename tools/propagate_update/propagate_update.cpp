#include "propagate_update.h"

/// @brief Constructor for the ssh_updater class.
/// @param config The ssh_config object containing the connection information for each raspberry pi.
ssh_updater::ssh_updater(ssh_config &config)
{
    int verbosity = SSH_LOG_NOLOG;
    int port = 22;
    int rc;

    this->session = ssh_new();
    this->host = config.host;
    if (this->session == NULL)
        exit(-1);

    ssh_options_set(this->session, SSH_OPTIONS_HOST, config.host.c_str());
    ssh_options_set(this->session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(this->session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(this->session, SSH_OPTIONS_SSH_DIR, config.path.c_str());

    // Connect to server
    rc = ssh_connect(this->session);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error connecting to localhost: %s\n",
                ssh_get_error(this->session));
        ssh_free(this->session);
        exit(-1);
    }

    // Authenticate ourselves
    rc = ssh_userauth_password(this->session, config.username.c_str(), config.password.c_str());
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(this->session));
        ssh_disconnect(this->session);
        ssh_free(this->session);
        exit(-1);
    }

    std::cout << "-- Connected to " << config.host << " --" << std::endl
              << std::endl;
}

/// @brief Destructor for the ssh_updater class
ssh_updater::~ssh_updater()
{
    // Disconnect from server
    disconnect();
}

/// @brief Update of the platform C++ project on the remote machine. It will install the required packages, copy the files and build the project.
/// @param path The path to the platform C++ project on the local machine.
/// @return 0 if the update was successful, -1 otherwise.
int ssh_updater::run_update(const std::string &path)
{
    std::cout << "Running update on " << path << std::endl
              << std::endl;

    // Install the required packages for the platform project
    if (ssh_updater::install_packages({"git", "cmake", "libssh-dev", "libjsoncpp-dev"}) != 0)
    {
        std::cout << "Error while installing packages" << std::endl;
        return -1;
    }

    // Create the directory where the project will be copied
    if (ssh_updater::run_command("cd Documents && mkdir Kevin_Bachelor_Thesis") != 0)
    {
        std::cout << "Error while creating directory" << std::endl;
        return -1;
    }

    // Get all the files to copy using the add_files_from_dir function and the /* glob
    std::vector<std::string> files = {"platform/*"};
    add_files_from_dir(&files, path);

    // Copy the files to the remote machine by using the send_files function
    if (ssh_updater::send_files(path, "/home/pi/Documents/Kevin_Bachelor_Thesis", files) != 0)
    {
        std::cout << "Error while sending files" << std::endl;
        return -1;
    }

    // Remove the CMakeCache.txt file to force a rebuild of the project, then build the project with cmake and make
    if (ssh_updater::run_command("cd Documents/Kevin_Bachelor_Thesis/platform && rm -rf CMakeCache.txt && cmake . && make") != 0)
    {
        std::cout << "Error while building" << std::endl;
        return -1;
    }
    return 0;
}

/// @brief Run a command on the remote machine.
/// @param command Command to run on the remote machine.
/// @return 0 if the command was successful, -1 otherwise.
int ssh_updater::run_command(const std::string &command)
{
    // Initialize the channel
    ssh_channel channel;
    int rc;
    char buffer[256];
    unsigned int nbytes;

    channel = ssh_channel_new(this->session);
    if (channel == NULL)
        return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }

    // Run the command
    rc = ssh_channel_request_exec(channel, command.c_str());
    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    // Read the output of the command
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes > 0)
    {
        if (write(1, buffer, nbytes) != (int)nbytes)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    // Close the channel in case of error
    if (nbytes < 0)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return SSH_ERROR;
    }

    // Close the channel and free the memory
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_OK;
}

/// @brief Disconnect from the remote machine and free the memory.
void ssh_updater::disconnect()
{
    ssh_disconnect(this->session);
    ssh_free(this->session);
    std::cout << std::endl
              << "-- Disconnected from " << this->host << " --" << std::endl
              << std::endl;
}

/// @brief Install the required packages and their dependencies on the remote machine which is not connected to the internet.
/// @param packages List of packages to install
/// @return 0 if the installation was successful, -1 otherwise.
int ssh_updater::install_packages(const std::vector<std::string> &packages)
{

    // Inspired from https://stackoverflow.com/a/41428445 for installing packages and their dependencies offline

    // Set the packages as a string
    std::string packages_string = "";
    for (std::string package : packages)
    {
        packages_string += package + " ";
    }

    // Create a local directory to store the packages and their dependencies that we will download
    std::filesystem::create_directory("temp_deb");
    std::string command = "cd temp_deb && apt-get download $(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances " + packages_string + " | grep \"^\\w\" | sort -u)";
    system(command.c_str());
    command = "cd temp_deb && dpkg-scanpackages . | gzip -9c > Packages.gz";
    system(command.c_str());

    // Now we have to copy the packages to the remote machine
    std::string temp_deb_directory_path = std::filesystem::current_path().string() + "/temp_deb";
    std::vector<std::string> filenames;

    // Get all the filenames in the directory temp_deb
    for (const auto &entry : std::filesystem::directory_iterator(temp_deb_directory_path))
    {
        std::string relative_path = entry.path().string().substr(temp_deb_directory_path.length() + 1, entry.path().string().length() - temp_deb_directory_path.length() - 1);
        filenames.push_back(relative_path);
    }

    // Create a directory on the remote machine to store the packages and their dependencies
    if (ssh_updater::run_command("mkdir /home/pi/temp_deb") != 0)
    {
        std::cout << "Error while creating directory" << std::endl;
        return -1;
    }

    // Copy the packages and their dependencies to the remote machine in the directory /home/pi/temp_deb
    if (ssh_updater::send_files(temp_deb_directory_path, "/home/pi/temp_deb", filenames) != 0)
    {
        std::cout << "Error while sending files" << std::endl;
        return -1;
    }

    // Add the directory to the sources.list file and update the packages. Also check if the directory is already in the sources.list file, if yes then do not add it again.
    command = "grep -qxF 'deb [trusted=yes] file:/home/pi/temp_deb ./' /etc/apt/sources.list || echo 'deb [trusted=yes] file:/home/pi/temp_deb ./' >> /etc/apt/sources.list";
    if (ssh_updater::run_command(command + " && sudo apt update && sudo apt install -y " + packages_string) != 0)
    {
        std::cout << "Error while installing packages" << std::endl;
        return -1;
    }
    return 0;
}

/// @brief Send files to the remote machine using scp.
/// @param from_path Path of the directory from which the files will be sent. The filename should be relative to this path.
/// @param target_path Path of the directory on the remote machine to which the files will be sent.
/// @param filenames List of filenames to send.
/// @return 0 if the files were sent successfully, -1 otherwise.
int ssh_updater::send_files(const std::string &from_path, const std::string &target_path, const std::vector<std::string> &filenames)
{
    // Initialize scp session
    ssh_scp scp;
    int rc;
    scp = ssh_scp_new(this->session, SSH_SCP_WRITE | SSH_SCP_RECURSIVE, target_path.c_str());
    if (scp == NULL)
    {
        fprintf(stderr, "Error allocating scp session: %s\n",
                ssh_get_error(this->session));
        return SSH_ERROR;
    }
    rc = ssh_scp_init(scp);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error initializing scp session: %s\n",
                ssh_get_error(this->session));
        ssh_scp_free(scp);
        return rc;
    }
    std::cout << "Sending files..." << std::endl;
    // Install each file one by one
    for (std::string filename : filenames)
    {
        // Clean the filename from any leading or trailing slashes and store it in filepath
        std::string filepath;

        // Check if their is a leading slash
        if (filename[0] == '/')
            filepath = filename.substr(1);
        else
            filepath = filename;

        // Check if the path ends with a slash
        if (filepath.ends_with("/"))
            filepath = filepath.substr(0, filepath.size() - 1);

        // Get the directory and filename
        std::string dir = filepath.substr(0, filepath.find_last_of("/"));
        std::string file = filepath.substr(filepath.find_last_of("/") + 1);

        // Check if the filepath is a directory or a file
        bool is_dir = filepath.find("/") != std::string::npos;
        std::vector<std::string> directories = split_dir(dir);
        if (is_dir)
        {
            // Create the directories on the remote machine recursively
            for (std::string sub_dir : directories)
            {
                // Add the right permissions that are needed to create the directory, usually executable for all
                rc = ssh_scp_push_directory(scp, sub_dir.c_str(), S_IRWXU | S_IXGRP | S_IRGRP | S_IXOTH);
                if (rc != SSH_OK)
                {
                    fprintf(stderr, "Can't create remote directory %s: %s\n",
                            sub_dir.c_str(), ssh_get_error(this->session));
                    std::cout << "Skipping directory " << sub_dir << std::endl;
                }
            }
        }

        // Open the local file
        if (from_path.ends_with("/"))
            filepath = from_path + filepath;
        else
            filepath = from_path + "/" + filepath;

        FILE *local = fopen(filepath.c_str(), "r");
        struct stat file_stat;
        stat(filepath.c_str(), &file_stat);
        if (local == NULL)
        {
            fprintf(stderr, "Can't open local file %s: %s\n",
                    filepath.c_str(), strerror(errno));
            ssh_scp_close(scp);
            ssh_scp_free(scp);
            return SSH_ERROR;
        }

        // Set the right permissions for the file
        mode_t mode = S_IRUSR | S_IWUSR | S_IWGRP | S_IRGRP | S_IROTH;
        mode = access(filepath.c_str(), X_OK) == 0 ? mode | S_IXUSR | S_IXGRP | S_IXOTH : mode;
        rc = ssh_scp_push_file(scp, file.c_str(), file_stat.st_size, mode);
        if (rc != SSH_OK)
        {
            fprintf(stderr, "Can't open remote file: %s\n",
                    ssh_get_error(this->session));
        }

        // Write the file to the remote machine by reading it from the local machine
        int nread;
        char buffer[16384];
        nread = fread(buffer, 1, sizeof(buffer), local);
        if (nread == 0){
            ssh_scp_write(scp, buffer, nread);
        }
        while (nread > 0)
        {
            if (ssh_scp_write(scp, buffer, nread) != SSH_OK)
            {
                fprintf(stderr, "Error writing to scp session: %s\n",
                        ssh_get_error(this->session));
                fclose(local);
                ssh_scp_close(scp);
                ssh_scp_free(scp);
                return SSH_ERROR;
            }
            nread = fread(buffer, 1, sizeof(buffer), local);
        }
        fclose(local);

        // Leave the directories that were created recursively for some
        if (is_dir)
        {
            for (int i = 0; i < directories.size(); i++)
            {
                ssh_scp_leave_directory(scp);
            }
        }
    }

    // Close the scp session and free the memory
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    return SSH_OK;
}

/// @brief Helper function to split a directory path into a vector of directories. This will be used to create the directories (recursively) on the remote machine.
/// @param path Path of the directory to split.
/// @return Vector of directories to create.
std::vector<std::string> ssh_updater::split_dir(const std::string &path)
{
    std::vector<std::string> directories;
    std::string current = "";
    for (char c : path)
    {
        if (c == '/')
        {
            directories.push_back(current);
            current = "";
        }
        else
        {
            current += c;
        }
    }
    directories.push_back(current);
    return directories;
}

/// @brief Helper function to add all files recursively from a directory to a vector of files, by replacing the wildcard with the actual files.
/// @param files Vector of files to add the files to. It will add to the vector where there might be actual files and remove the wildcard.
/// @param path Path of the directory to add the files from.
void add_files_from_dir(std::vector<std::string> *files, const std::string &path)
{
    // Loop through all files and check if there is a wildcard
    for (size_t i = 0; i < files->size(); i++)
    {
        if (files->at(i).find("/*") != std::string::npos)
        {
            // Get the directory and add all files recursively to the vector
            std::string dir;
            if (path.ends_with("/"))
                dir = path + files->at(i).substr(0, files->at(i).find("/*"));
            else
                dir = path + "/" + files->at(i).substr(0, files->at(i).find("/*"));

            // Use the filesystem library and the recursive_directory_iterator to get all files recursively. Then add them to the vector.
            for (const auto &entry : std::filesystem::recursive_directory_iterator(dir))
            {
                struct stat st;
                stat(entry.path().string().c_str(), &st);
                if (S_ISDIR(st.st_mode))
                    continue;
                std::string relative_path = entry.path().string().substr(path.length() + 1, entry.path().string().length() - path.length() - 1);
                files->push_back(relative_path);
            }
            // Remove the wildcard from the vector
            files->erase(files->begin() + i);
        }
    }
}