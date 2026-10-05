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

        if ($user == '' || $pass == '' || !isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER'] != $user || $_SERVER['PHP_AUTH_PW'] != $pass) {
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
            $backup = &$this->dbutil->backup();
        }

        // Load the download helper and send the file to your desktop
        $this->load->helper('download');
        force_download('stikked.gz', $backup);
    }

    private function _dump_postgre()
    {
        $dump = "-- Stikked data dump\n";

        foreach ($this->db->list_tables() as $table) {
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
