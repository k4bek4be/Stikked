<?php if (!defined('BASEPATH')) {
    exit('No direct script access allowed');
}

#[\AllowDynamicProperties]
class Backup extends CI_Controller
{

    public function __construct()
    {
        parent::__construct();

        //protection
        $user = $this->config->item('backup_user');
        $pass = $this->config->item('backup_pass');

        // FastCGI doesn't provide PHP_AUTH_USER and PHP_AUTH_PW
        if (empty($_SERVER['PHP_AUTH_USER']) && empty($_SERVER['PHP_AUTH_PW']) && !empty($_SERVER['HTTP_AUTHORIZATION'])) {
            $credentials = explode(':', (string) base64_decode(substr($_SERVER['HTTP_AUTHORIZATION'], 6)), 2);
            $_SERVER['PHP_AUTH_USER'] = $credentials[0];
            $_SERVER['PHP_AUTH_PW'] = isset($credentials[1]) ? $credentials[1] : '';
        }
        $given_user = isset($_SERVER['PHP_AUTH_USER']) ? (string) $_SERVER['PHP_AUTH_USER'] : '';
        $given_pass = isset($_SERVER['PHP_AUTH_PW']) ? (string) $_SERVER['PHP_AUTH_PW'] : '';

        if ($user == '' || $pass == '' || !hash_equals((string) $user, $given_user) || !hash_equals((string) $pass, $given_pass)) {
            header('WWW-Authenticate: Basic realm="Backup"');
            header('HTTP/1.0 401 Unauthorized');
            exit;
        }
    }

    public function index()
    {

        // Load the DB utility class
        $this->load->dbutil();

        // Backup your entire database and assign it to a variable
        if ($this->db->dbdriver == 'postgre') {
            // CodeIgniter's backup() is not supported on PostgreSQL, dump the data ourselves
            $backup = gzencode($this->_dump_postgre());
        } else {
            $backup = $this->dbutil->backup(array('ignore' => array($this->db->dbprefix('sessions'))));
        }

        // Load the download helper and send the file to your desktop
        $this->load->helper('download');
        force_download('stikked.gz', $backup);
    }

    private function _dump_postgre()
    {
        $dump = "-- Stikked data dump\n";

        foreach ($this->db->list_tables() as $table) {
            // session ids would allow hijacking logged-in sessions
            if ($table === $this->db->dbprefix('sessions')) {
                continue;
            }
            $rows = $this->db->get($table)->result_array();

            foreach ($rows as $row) {
                $values = array();

                foreach ($row as $value) {
                    $values[] = ($value === null) ? 'NULL' : $this->db->escape($value);
                }
                $dump .= 'INSERT INTO ' . $this->db->protect_identifiers($table, true) . ' (' . implode(', ', array_map(array($this->db, 'escape_identifiers'), array_keys($row))) . ') VALUES (' . implode(', ', $values) . ");\n";
            }
        }
        return $dump;
    }
}
