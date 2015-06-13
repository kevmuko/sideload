#!/usr/bin/python
# -*- coding: utf-8 -*- 
import os
import time
import codecs
 
class GenCsr(object):
    __usage__ = '''
    Generates a csr based on the given parameters
    SET UP  :
        OPENSSL shall be installed and added to path and
        python shall be installed and added to path
        download python from here : version - 2.7.* for 32 bit
        http://www.python.org/ftp/python/2.7.6/python-2.7.6.msi
 
    USAGE :
        x1 = GenCsr()
        print x1.type_RSA(
            'abc.com','org','ou','locality','state','IN',2048,'sha256')
        print x1.type_DSA(
            'abc.com','org','ou','locality','state','IN',2048,'sha256')
        print x1.type_ECC(
            'abc.com','org','ou','locality','state','IN',2048,'sha256')
 
    the private key and csr stored as /csr/cn.key and /csr/cn.csr
    __maintainer__ = ''
 
    '''
    # support added for multiple sans in csr
    # added calls for rsa , dsa and ecc separately :
    # .type_RSA() ,.type_DSA(). type_ECC()
    # print commands made python 3 compatible
    # TODO: implement python2/3 compatibility for unicode strings
 
    def __init__(self):
        fpath = os.path.join('.', 'csr')  # creates .\csr ( os wise)
        if not os.path.exists(fpath):
            os.mkdir(fpath)
        self.csr_path = os.path.join(fpath, 'cn.csr')
        self.pvtkey_path = os.path.join(fpath, 'cn.key')
        self.conf_path = os.path.join(fpath, 'cn.conf.txt')
        self.dsaparampath = os.path.join(fpath, 'dsaparam.pem')
        self.eccparampath = os.path.join(fpath, 'eccparam.pem')
 
    def _clean_old_files(self):
        for file in [self.csr_path,
                     self.conf_path,
                     self.pvtkey_path,
                     self.dsaparampath,
                     self.eccparampath]:
            if(os.path.isfile(file)):
                os.remove(file)
 
    def _gen_openssl_conf(self):
        f = codecs.open(self.conf_path, 'w', 'utf-8')
        #f = codecs.open(self.conf_path, 'w')
        #if str(self.Sig_Alg).upper()== 'DSA': self.hash_alg='sha256'
        f.write(u'[ req ]\
                {nl}default_bits={keysize}\
                {nl}prompt = no\
                {nl}encrypt_key = no\
                {nl}distinguished_name = dn\
                {nl}default_md={hash_alg}{nl}'.format(
                keysize=self.Key_Size,
                hash_alg=self.hash_alg,
                nl='\n'))
        #to add challenge password {nl}attributes=req_attributes{nl}
        sanincsrFlag = None
        if self.SanInCSR is not None and self.SanInCSR != []:
            f.write("req_extensions = req_ext{nl}".format(nl='\n'))
            sanincsrFlag = True
        # format - unicode
        # http://stackoverflow.com/questions/3235386
        #/python-using-format-on-a-unicode-escaped-string
        f.write(u'{nl}[dn]\
               {nl}CN ={cn}\
               {nl}emailAddress = {email}\
               {nl}O = {org}\
               {nl}L = {locality}\
               {nl}ST = {state}\
               {nl}C = {country}\
               {nl}0.OU = {org_unit}{nl}'.format(
                cn=self.CN.decode('utf-8'),
                email=self.O.decode('utf-8'),
                org=self.OU.decode('utf-8'),
                locality=self.L.decode('utf-8'),
                state=self.ST.decode('utf-8'),
                country=self.C.decode('utf-8'),
                org_unit=self.OU.decode('utf-8'),
                nl='\n'))
 
        if sanincsrFlag : 
            f.write(u'{nl}[ req_ext ]\
                     {nl}subjectAltName = @alt_names{nl}\
                     {nl}[alt_names]'.format(nl='\n'))
 
            for i, san in enumerate(self.SanInCSR):
                f.write(u'{nl}DNS.{count}= {san}'.format(
                    nl='\n', count=str(i+1), san=san.decode('utf-8')))
        if False:  #https://www.openssl.org/docs/apps/req.html#COMMAND-OPTIONS
            f.write('\n[ req_attributes ]\nchallengePassword = P@ssword\n')
        f.close()
 
    def _gen_csr(self):
        self.csr = None
        self._clean_old_files()
        self._gen_openssl_conf()
        func_call_dict = {'DSA': self._gen_dsa_keypair,
                          'ECC': self._gen_ecc_keypair,
                          'RSA': self._gen_rsa_keypair,
                          }
        func_call_dict[self.Sig_Alg.upper()]()
        csrGenCommand = 'openssl req -new -utf8 -key {keyfile} -out {csrfile} -config {configfile} '.format(
                        keyfile=self.pvtkey_path,
                        csrfile=self.csr_path,
                        configfile=self.conf_path)
        #print csrGenCommand
        os.popen(csrGenCommand)
        #print('{nl}csr saved in file :{nl} {csrfile}\
        #       {nl}private key saved in file :{nl} {keyfile}'.format(
        #        nl='\n',
        #        csrfile=os.path.abspath(self.csr_path),
        #        keyfile=os.path.abspath(self.pvtkey_path)))            
        self._read_csr_from_file()
 
    def _gen_dsa_keypair(self):
        newKeyParam = 'dsa:'+self.dsaparampath
        # Generate the Dsa Params for dsa ( p q and G)
        dsaParamGenCommand = "openssl  dsaparam " + self.Key_Size  + " -out " + self.dsaparampath # ( for dsa key size can be 2048 or 2048-256, like using subprimes)
        dsaPvtKeyGenCommand = "openssl gendsa  -out " +self.pvtkey_path + " " +self. dsaparampath
        #print('dsa param\n{dsaParamGenCommand}\ndsa pvtkey\n{dsaPvtKeyGenCommand}\n'.format(
        #    dsaParamGenCommand=dsaParamGenCommand,
        #    dsaPvtKeyGenCommand=dsaPvtKeyGenCommand))
        os.popen(dsaParamGenCommand)
        os.popen(dsaPvtKeyGenCommand)
 
    def _gen_ecc_keypair(self):
        if str(self.Key_Size).isdigit():
            self.Key_Size = 'prime256v1'
        eccParamGenCommand = "openssl ecparam -name " + self.Key_Size + "  -genkey -out " + self.pvtkey_path
        #print('EC Param Generation\n{}'.format(eccParamGenCommand))
        os.popen(eccParamGenCommand)
 
    def _gen_rsa_keypair(self):
        rsaPvtKeyGenCommand = "openssl genrsa -out " +self.pvtkey_path + " " + self.Key_Size 
        os.popen(rsaPvtKeyGenCommand)
        #print 'RSA Private Key Generation\n{}'.format(rsaPvtKeyGenCommand)
 
    def _read_csr_from_file(self):
        if os.path.exists(self.csr_path):
            with open(self.csr_path, 'r') as f:
                self.csr = f.read()
            return self.csr
        else:
            #print('{}'.format('csr not created ................'))
            return False
 
    def get_csr(self, CN, O, OU, L, ST, C, Signing_Algorithm,
                keysize=2048, hash_alg='sha256', SanInCSR=[]):
        self.CN = CN
        self.SanInCSR = SanInCSR
        self.O = O
        self.OU = OU
        self.L = L
        self.ST = ST
        self.C = C
        self.Sig_Alg = Signing_Algorithm
        self.Key_Size = str(keysize)
        self.hash_alg = hash_alg
        self._gen_csr()
        #self.gen_loadrunner_csr()
        #print self.csr
        return self.csr
 
    def type_RSA(self, CN, O, OU, L, ST, C,
                 keysize=2048,
                 hash_alg='sha256',
                 SanInCSR=[]):
        #print('{}'.format('=' * 40))
        #print('{}'.format('System call to generate a RSA csr'))
        #print('{}'.format('=' * 40))
        return self.get_csr(CN, O, OU, L, ST, C, 'RSA',
                            keysize, hash_alg, SanInCSR)
 
    def type_DSA(self, CN, O, OU, L, ST, C,
                 keysize=2048,
                 hash_alg='sha256',
                 SanInCSR=[]):
        #print('{}'.format('=' * 40))
        #print('{}'.format('System call to generate a DSA csr'))
        #print('{}'.format('=' * 40))
        return self.get_csr(CN, O, OU, L, ST, C,
                            'DSA', keysize, hash_alg, SanInCSR)
 
    def type_ECC(self, CN, O, OU, L, ST, C,
                 curve_name='prime256v1',
                 hash_alg='sha256',
                 SanInCSR=[]):
        # if you want to use a specific curve to use provide as keysize param
        #print('{}'.format('=' * 40))
        #print('{}'.format('System call to generate a ECC csr'))
        #print('{}'.format('=' * 40))
        return self.get_csr(CN, O, OU, L, ST, C, 'ECC',
                            curve_name, hash_alg, SanInCSR)
 
    def gen_loadrunner_csr(self):
        '''This function creates load runner required csr
         format from the csr generated 
        fileout = 'load_runner_csr' + str(int(time.time())) + '.txt'
        if not os.path.exists(fileout):
            open(fileout, 'w').close()  # creates an empty file
        with open(fileout, 'a') as f:
            csr_string = ''
            with open(self.csr_path, 'r') as r:
                for line in r.readlines():
                    csr_string += line.replace('\n', '||')
                csr_string += '\n'
            f.write(csr_string)'''
        pass