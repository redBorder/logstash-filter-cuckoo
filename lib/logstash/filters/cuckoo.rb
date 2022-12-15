# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'yaml'
require 'json'
require 'rest-client'
require 'digest'

class LogStash::Filters::Cuckoo < LogStash::Filters::Base

  config_name "cuckoo"

  # Hostname where cuckoo_api is running
  config :cuckoo_server,                            :validate => :string,   :default => "localhost:8090"
  config :cuckoo_exclude_file_types,                :validate => :array,    :default => []
  config :cuckoo_file,                              :validate => :string,   :default => "[path]"

  config :file_bin_path,                            :validate => :string,   :default => "/usr/bin/file"
  config :tag_on_create_cuckoo_task_failure,        :validate => :array,    :default => ['_createcuckootaskfailure'] 

  public
  def register
  end # def register

  private

  # Send file to be analyzed by cuckoo.
  # @return returns cuckoo analysis task id.
  def create_cuckoo_task(file_path)
    task_id = nil
 
    begin
      file_name = ::File.basename(file_path)
      file =      ::File.open(file_path, 'r')
      options = {filename: file_name, file: file}
    rescue Errno::ENOENT=> ex
      @logger.error(ex.message)
      return task_id
    rescue Errno::EACCES=> ex
      @logger.error(ex.message)
      return task_id
    end
 
    begin
      response = RestClient::Request.execute(
        method: "post",
        url: "http://#{@cuckoo_server}/tasks/create/file",
        payload: options,
        timeout: 120
      )
    rescue RestClient::Exception => ex
      @logger.error(ex.message)
      return task_id
    end
    JSON.parse(response.body)["task_ids"] rescue nil 
  end 


  def detect_mime_type(file_path)
    # if the user has installed file binary, we can use that
    # if not, return nil
    return nil unless File.exist?(@file_bin_path)
  
    # Attempt to detect the MIME type using the file binary
    type, _ = `#{@file_bin_path} --mime -b #{file_path}`.split('; ') rescue nil
  
    # Return the MIME type as a string, or nil if it could not be detected
    type ? type.to_s : nil
  end
  
  public
  def filter(event)
    begin
      @logger.info("[Cuckoo] Checking event #{event}")

      cuckoo_file_path = event.get(@cuckoo_file)

      unless cuckoo_file_path and File.exist?cuckoo_file_path and !@cuckoo_exclude_file_types.include? detect_mime_type(cuckoo_file_path)
         @logger.info("[Cuckoo] Nothing to do.")
         return
      end

      @logger.info("[Cuckoo] Sending file to be analyzed.")
      cuckoo_task_id = create_cuckoo_task(cuckoo_file_path)
      
      if cuckoo_task_id
        event.set("cuckoo_task_id", cuckoo_task_id) if cuckoo_task_id
      else
        @tag_on_create_cuckoo_task_failure.each { |tag| event.tag(tag) }
      end

    rescue => e
      @logger.error(e.message)
    end

    @logger.info("[Cuckoo] output event: #{event}")

    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Cuckoo
