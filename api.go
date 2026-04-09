// package dnscache provides an example async and multithreaded map based dnscache
package dnscache

// import
import (
	"errors"
	"net"
	"strings"
)

var (
	StatsQueries uint64
	StatsHits    uint64
	StatsMisses  uint64
)

//
// SIMPLE STDLIB "NET" PKG API COMPATIBLE INPLACE
//

// LookupIP ...
func LookupIP(host string) ([]net.IP, error) {
	if ip, ok := getIP(host); ok {
		return ip, nil
	}
	ip, err := net.LookupIP(host)
	if err != nil {
		return ip, err
	}
	dnsIPChan <- dnsIP{host, ip}
	return ip, nil
}

// LookupHost ...
func LookupHost(host string) ([]string, error) {
	if addrs, ok := getHost(host); ok {
		return addrs.([]string), nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return []string{}, err
	}
	dnsHostChan <- dnsHost{host, addrs}
	return addrs, nil
}

// LookupCNAME ...
func LookupCNAME(host string) (string, error) {
	if addrs, ok := getHost(host + _cname); ok {
		return addrs.(string), nil
	}
	addrs, err := net.LookupCNAME(host)
	if err != nil {
		return _empty, err
	}
	dnsHostChan <- dnsHost{host + _cname, addrs}
	return addrs, nil
}

// LookupMX ...
func LookupMX(host string) ([]*net.MX, error) {
	if addrs, ok := getHost(host + _mx); ok {
		return addrs.([]*net.MX), nil
	}
	addrs, err := net.LookupMX(host)
	if err != nil {
		return nil, err
	}
	dnsHostChan <- dnsHost{host + _mx, addrs}
	return addrs, nil
}

// LookupNS ...
func LookupNS(host string) ([]*net.NS, error) {
	if addrs, ok := getHost(host + _ns); ok {
		return addrs.([]*net.NS), nil
	}
	addrs, err := net.LookupNS(host)
	if err != nil {
		return nil, err
	}
	dnsHostChan <- dnsHost{host + _ns, addrs}
	return addrs, nil
}

// LookupTXT ...
func LookupTXT(host string) ([]string, error) {
	if addrs, ok := getHost(host + _txt); ok {
		return addrs.([]string), nil
	}
	addrs, err := net.LookupTXT(host)
	if err != nil {
		return nil, err
	}
	dnsHostChan <- dnsHost{host + _txt, addrs}
	return addrs, nil
}

// LookupSRV ...
func LookupSRV(service, proto, name string) (string, []*net.SRV, error) {
	if addrs, ok := getHost(service + proto + name + _srv); ok {
		e := addrs.([]*net.SRV)
		s := strings.Split(e[0].Target, _sep)
		if len(s) == 2 {
			e[0].Target = s[0]
			return s[1], e, nil
		}
		return _empty, nil, errors.New("[dnscache] [internal error] [unable to decode srv record]")
	}
	cname, addrs, err := net.LookupSRV(service, proto, name)
	if err != nil {
		return _empty, nil, err
	}
	s := addrs
	s[0].Target = s[0].Target + _sep + cname
	dnsHostChan <- dnsHost{service + proto + name + _srv, s}
	return cname, addrs, nil
}

// LookupAddr ...
func LookupAddr(addr string) ([]string, error) {
	if hosts, ok := getHost(addr + _ptr); ok {
		return hosts.([]string), nil
	}
	hosts, err := net.LookupAddr(addr)
	if err != nil {
		return []string{}, err
	}
	dnsHostChan <- dnsHost{addr + _ptr, hosts}
	return hosts, nil
}

//
// ADDITIONAL NEW INTERFACES
//

// CleanCache ...
func CleanCache() {
	cleanCacheAll()
}
