require "pem2xml/version"
require 'thor'
require 'openssl'
require 'rexml/document'
require 'base64'

module Pem2xml

  def self.main()
    file_name = ARGV[0]
    raise "key file doesn't exists" if (file_name == nil) || !File.exists?(file_name)
    p "loading #{file_name}"
    file = File.open file_name
    key = OpenSSL::PKey::RSA.new file
    p key.to_xml.to_s
  end

  class OpenSSL::BN
    def to_base64
      Base64.strict_encode64 self.to_s 2
    end
  end

  class OpenSSL::PKey::RSA
    def to_xml
      self.private? ? Pem2xml.process_private(self) : Pem2xml.process_public(self)
    end
  end

  def self.process_private(key)
    doc = RSAXML.new
    params = {
      'Modulus' => key.n.to_base64,
      'Exponent' => key.e.to_base64,
      'P' => key.p.to_base64,
      'Q' => key.q.to_base64,
      'DP' => key.dmp1.to_base64,
      'DQ' => key.dmq1.to_base64,
      'InverseQ' => key.iqmp.to_base64,
      'D' => key.d.to_base64,
    }
    doc.add_params params
    return doc
  end
  
  def self.process_public(key)
    doc = RSAXML.new
    params = {
      'Modulus' => key.n.to_base64,
      'Exponent' => key.e.to_base64,
    }
    doc.add_params params
    return doc
  end

  class RSAXML < REXML::Document
    def initialize
      super
      @rsaKeyValue = self.add_element 'RSAKeyValue'
    end

    def add_param(key, value)
      element = @rsaKeyValue.add_element key
      element.add_text value
    end

    def add_params(params)
      params.each do |key, value|
        self.add_param key, value
      end 
    end
  end
end
