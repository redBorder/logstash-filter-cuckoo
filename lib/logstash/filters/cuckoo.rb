# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'yaml'
require 'json'
require 'rest-client'
require 'digest'

require 'mime/types'
# require 'filemagic'

class LogStash::Filters::Cuckoo < LogStash::Filters::Base

  config_name "cuckoo"

  # Hostname where cuckoo_api is running
  config :host,                           :validate => :string,   :default => "localhost:8090"
  config :file_path,                      :validate => :string,   :required => true
  
  # Config file where are set cuckoo excluded mime types
  config :config_file,                        :validate => :string,   :default => "/opt/rb/var/rb-sequence-oozie/conf/config.yml"

  public
  def register

  end # def register

  private

  # # Check file mime type
  # # @return boolean whether file mime type is excluded for analysis or not
  # def filetype_is_excluded?(file_mime_type)
  #   begin
  #     filters = YAML.load_file(@config_file)["cuckoo"]["cuckoo_filters"]
  #     filters.include? file_mime_type
  #   rescue Errno::ENOENT => e
  #     nil
  #   end
  # end

  # # Send file to be analyzed by cuckoo.
  # # @return returns cuckoo analysis task id.
  # def send_file
  #   @logger.info("Sending file to be analyzed.")

  #   task_id = nil

  #   begin
  #     file_name = ::File.basename(@path)
  #     file =      ::File.open(@path, 'r')
  #     options = {filename: file_name, file: file}
  #   rescue Errno::ENOENT=> ex
  #     @logger.error(ex.message)
  #     return task_id
  #   rescue Errno::EACCES=> ex
  #     @logger.error(ex.message)
  #     return task_id
  #   end


  #   begin
  #     response = RestClient::Request.execute(
  #       method: "post",
  #       url: "http://#{@host}/tasks/create/file",
  #       payload: options
  #     )
  #   rescue RestClient::Exception => ex
  #     @logger.error(ex.message)
  #     return task_id
  #   end

  #   JSON.parse(response.body)["task_ids"]

  # end

  public
  def filter(event)
    @logger.info("[Cuckoo] processing #{@file_path}")

    begin
      return unless File.exists?(filename)
      mime_type = MIME::Types.type_for(filename).first

      @logger.info("File #{@file_path)} mime type is #{mime_type}")

      excluded = filetype_is_excluded?(mime_type)

      # if excluded
      #   @logger.info("Mime type #{mime_type} is excluded from Cuckoo Analysis")
      # elsif excluded.nil?
      #   @logger.error("Error parsing file #{@config_file}.")
      # else
      #   task_id = send_file
      #   if task_id
      #     @logger.info("Task #{task_id} has been created.")
      #   else
      #     @logger.info("There was an error creating Cuckoo task. Check filter configuration and cuckoo_api service status.")
      #   end
      # end
    rescue => e
      @logger.error(e.message)
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Cuckoo