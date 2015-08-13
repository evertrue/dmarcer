require 'dmarcer/version'
require 'nokogiri'
require 'resolv'

module Dmarcer
  class Parser
    def initialize(input_file)
      @input_file = input_file
    end

    def record_by_identifier(identifier)
      data.record.select { |r| r.identifiers.header_from.content == identifier }
    end

    def identifiers
      data.record.map { |r| r.identifiers.header_from.content }.uniq.sort
    end

    def org_name
      data.report_metadata.org_name.content
    end

    def date_range
      t_begin = Time.at(data.report_metadata.date_range.begin.content.to_i)
      t_end = Time.at(data.report_metadata.date_range.end.content.to_i)
      t_begin..t_end
    end

    def id
      data.report_metadata.report_id.content
    end

    def records
      @records ||= @data.record.map { |r| Record.new r }
    end

    def dkim_auth_failure_records
      records.select { |r| r.auth_failed_dkim_domains.any? }
    end

    def spf_auth_failure_records
      records.select { |r| r.auth_failed_spf_domains.any? }
    end

    def spf_domain_ip_hash
      spf_auth_failure_records.each_with_object({}) do |r, m|
        r.auth_failed_spf_domains.each do |d|
          if m[d]
            m[d] << r.source_ip
          else
            m[d] = [r.source_ip]
          end
        end
      end
    end

    def print_report
      puts "Report Organization: #{org_name}"
      puts "Report ID: #{id}"
      puts "Date Range: #{date_range}"
      puts ''
      puts '------------------ SPF Failures ------------------'
      # spf_auth_failure_records.each do |r|
      #   puts "Source IP: #{r.source_ip} (#{lookup(r.source_ip)})"
      #   puts "Auth failed SPF domains: #{r.auth_failed_spf_domains.join(', ')}"
      #   puts ''
      # end
      spf_domain_ip_hash.each do |domain, ips|
        puts domain
        ips.each { |ip| puts "  #{lookup(ip)} [#{ip}]" }
        puts ''
      end
      puts '------------------ DKIM Failures ------------------'
      dkim_auth_failure_records.each do |r|
        puts "Source IP: #{r.source_ip} (#{lookup(r.source_ip)})"
        unless r.auth_failed_dkim_domains == ['evertrue.com']
          puts "Auth failed DKIM domains: #{r.auth_failed_dkim_domains.join(', ')}"
          puts ''
        end
      end
    end

    private

    def lookup(ip)
      return Resolv.getname(ip) if ip !~ Resolv::IPv6::Regex
      'err IPv6 address'
    rescue Resolv::ResolvError
      nil
    end

    def data
      @data ||= Nokogiri::Slop(File.read(@input_file)).feedback
    end
  end

  class Record
    attr_accessor :data

    def initialize(data)
      @data = data
    end

    def spf?
      @data.auth_results.respond_to?('spf')
    end

    def dkim?
      @data.auth_results.respond_to?('dkim')
    end

    def source_ip
      @data.row.source_ip.content
    end

    def header_from
      @data.identifiers.header_from.content
    end

    def count
      @data.row.count
    end

    def dkim_domains
      domains_by_record_type(:dkim)
    end

    def spf_domains
      domains_by_record_type(:spf)
    end

    def auth_failed_dkim_domains
      auth_failure_domains_by_record_type(:dkim)
    end

    def auth_failed_spf_domains
      auth_failure_domains_by_record_type(:spf)
    end

    def policy_eval
      p = @data.row.policy_evaluated
      {
        disposition: p.disposition.content,
        dkim: p.dkim.content,
        spf: p.spf.content
      }
    end

    private

    def domains_by_record_type(type)
      # rubocop:disable Metrics/LineLength
      return [] unless @data.auth_results.respond_to?(type)
      return [@data.auth_results.send(type).domain.content] if @data.auth_results.send(type).respond_to?('domain')
      @data.auth_results.send(type).map { |r| r.domain.content }.uniq.sort
      # rubocop:enable Metrics/LineLength
    end

    def auth_failure_domains_by_record_type(type)
      # rubocop:disable Metrics/LineLength
      return [] unless @data.auth_results.respond_to?(type)
      if @data.auth_results.send(type).respond_to?('result') &&
         @data.auth_results.send(type).result.content != 'pass'
        return [@data.auth_results.send(type).domain.content]
      end
      @data.auth_results.send(type)
        .select { |r| r.respond_to?(type) && r.send(type).result.content != 'pass' }
        .map { |r| r.domain.content }.uniq.sort
      # rubocop:enable Metrics/LineLength
    end
  end
end
