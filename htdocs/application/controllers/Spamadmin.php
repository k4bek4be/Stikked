<?php if (!defined('BASEPATH')) {
    exit('No direct script access allowed');
}

#[\AllowDynamicProperties]
class Spamadmin extends CI_Controller
{

    public function __construct()
    {
        parent::__construct();

        //protection
        $user = $this->config->item('spamadmin_user');
        $pass = $this->config->item('spamadmin_pass');

        // FastCGI doesn't provide PHP_AUTH_USER and PHP_AUTH_PW, apparently?
        if (empty($_SERVER['PHP_AUTH_USER']) && empty($_SERVER['PHP_AUTH_PW'])) {
            if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
                $credentials = explode(':', (string) base64_decode(substr($_SERVER['HTTP_AUTHORIZATION'], 6)), 2);
                $_SERVER['PHP_AUTH_USER'] = $credentials[0];
                $_SERVER['PHP_AUTH_PW'] = isset($credentials[1]) ? $credentials[1] : '';
            }
        }

        // If they're not set, set them to blank. The null coalesce operator would be handy here, but
        // that's PHP 7.0 and higher...
        if (empty($_SERVER['PHP_AUTH_USER'])) {
            $_SERVER['PHP_AUTH_USER'] = "";
        }
        if (empty($_SERVER['PHP_AUTH_PW'])) {
            $_SERVER['PHP_AUTH_PW'] = "";
        }

        if ($user === '' || $pass === '' || !is_string($user) || !is_string($pass) || !hash_equals($user, (string) $_SERVER['PHP_AUTH_USER']) || !hash_equals($pass, (string) $_SERVER['PHP_AUTH_PW'])) {
            header('WWW-Authenticate: Basic realm="Spamadmin"');
            header('HTTP/1.0 401 Unauthorized');
            exit;
        }
    }

    public function index()
    {
        $this->load->model('pastes');
        $pastes_to_delete = $this->input->post('pastes_to_delete');

        if ($pastes_to_delete) {
            $this->_require_same_origin();
            foreach (explode(' ', $pastes_to_delete) as $pid) {
                $this->db->where('pid', $pid);
                $this->db->delete('pastes');
            }
            redirect(site_url('spamadmin/' . $this->uri->segment(2)));
        }

        //render view
        $data = $this->pastes->getSpamLists();
        $this->load->view('list_ips', $data);
    }

    public function spam_detail()
    {
        $this->load->model('pastes');
        $ip_address = $this->uri->segment(2);

        if ($this->input->post('confirm_remove') && $ip_address != '') {
            $this->_require_same_origin();
            $this->db->where('ip_address', $ip_address);
            $this->db->delete('pastes');
            $paste_count = $this->db->affected_rows();

            if ($this->input->post('block_ip')) {
                $query = $this->db->get_where('blocked_ips', array(
                    'ip_address' => $ip_address,
                ));

                if ($query->num_rows() == 0) {
                    $this->db->insert('blocked_ips', array(
                        'ip_address' => $ip_address,
                        'blocked_at' => time(),
                        'spam_attempts' => $paste_count,
                    ));
                }
            }
        }

        //fill data
        $data = $this->pastes->getSpamLists('spamadmin/' . $ip_address, $seg = 3, $ip_address);
        $data['ip_address'] = $ip_address;
        $ip = explode('.', $ip_address);

        if (count($ip) > 1) {
            $ip_firstpart = $ip[0] . '.' . $ip[1] . '.';
            $data['ip_range'] = $ip_firstpart . '*.*';
        } else {

            // ipv6
            $ip = explode(':', $ip_address);
            $ip_firstpart = $ip[0] . ':' . $ip[1] . ':' . $ip[2] . ':' . $ip[3] . ':' . $ip[4] . ':' . $ip[5] . ':' . $ip[6];
            $data['ip_range'] = $ip_firstpart . ':*';
        }

        //view
        $this->load->view('spam_detail', $data);
    }

    public function blacklist()
    {

        //pagination
        $amount = $this->config->item('per_page');
        $page = ($this->uri->segment(3) ? $this->uri->segment(3) : 0);

        //get
        $this->db->select('ip_address, blocked_at, spam_attempts');
        $this->db->order_by('blocked_at desc, ip_address asc');
        $query = $this->db->get('blocked_ips', $amount, $page);
        $data['blocked_ips'] = $query->result_array();

        //pagination
        $config['base_url'] = site_url('spamadmin/blacklist');
        $query = $this->db->get('blocked_ips');
        $config['total_rows'] = $query->num_rows();
        $config['per_page'] = $amount;
        $config['num_links'] = 9;
        $config['full_tag_open'] = '<div class="pages">';
        $config['full_tag_close'] = '</div>';
        $config['uri_segment'] = 3;
        $this->load->library('pagination');
        $this->pagination->initialize($config);
        $data['pages'] = $this->pagination->create_links();

        //view
        $this->load->view('list_blocked_ips', $data);
    }

    public function unblock_ip()
    {
        $this->_require_same_origin();
        $ip_address = $this->uri->segment(4);
        $this->db->where('ip_address', $ip_address);
        $this->db->delete('blocked_ips');
        redirect('spamadmin/blacklist');
    }

    /**
     * CSRF protection for state-changing actions: browsers send the basic-auth
     * credentials automatically, so require that the request originates from this host.
     */
    private function _require_same_origin()
    {
        $source = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : (isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '');
        $parts = parse_url($source);
        $host = isset($parts['host']) ? $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '') : '';
        $own = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';

        if ($host === '' || strcasecmp($host, $own) !== 0) {
            show_error('Cross-site request rejected (missing or foreign Origin/Referer header).', 403);
        }
    }
}
