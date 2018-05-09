#!/usr/bin/ruby
# Project URL: https://github.com/jonjacksonma/panfsacl


require 'find'
require 'set'
require 'getoptlong'
USAGE_TEXT="
#{File.basename($0)} [-R] file ...

DESCRIPTION

This utility displays the active Panasas Access Control Lists (ACLs) on files and directories.  

OPTIONS
-R, --recursive
    List the ACLs of all files and directories recursively.

"

FILE_READ='rnkRP'
FILE_READ_FULL=Set.new(FILE_READ.split(''))
FILE_READ_FULL_LENGTH=FILE_READ_FULL.count

FILE_WRITE='wadNW'
FILE_WRITE_FULL=Set.new(FILE_WRITE.split(''))
FILE_WRITE_FULL_LENGTH=FILE_WRITE_FULL.count
  
DIR_READ='x'
DIR_READ_FULL = Set.new(FILE_READ_FULL + [DIR_READ])
DIR_READ_FULL_LENGTH=DIR_READ_FULL.count

DIR_WRITE='cCD'
DIR_WRITE_FULL= Set.new((DIR_WRITE + 'W').split(''))
DIR_WRITE_FULL_LENGTH=DIR_WRITE_FULL.count

EXEC='x'
EXEC_FULL=['x']
FULL='ops'

@permsinfo={
  'directory' => {
    'r' => { 
      'count' => DIR_READ_FULL_LENGTH,
      'aclcomps' => DIR_READ_FULL
    },
    'w' => {
      'count' => DIR_WRITE_FULL_LENGTH,
      'aclcomps' => DIR_WRITE_FULL
    },
  },
  'file' => {
    'r' => {
      'count' => FILE_READ_FULL_LENGTH,
      'aclcomps' => FILE_READ_FULL
    },
    'w' => {
      'count' => FILE_WRITE_FULL_LENGTH,
      'aclcomps' => FILE_WRITE_FULL
    },
  },
}

@recursive=false

opts = GetoptLong.new(
  [ '--debug', '-d', GetoptLong::NO_ARGUMENT],
  [ '--help', '-h', GetoptLong::NO_ARGUMENT ],
  [ '--verbose', '-v', GetoptLong::NO_ARGUMENT],
  [ '--recursive', '-R', GetoptLong::NO_ARGUMENT ]
)

opts.each do |opt, arg|
  case opt
  when '--debug'
    @debug=true
  when '--verbose'
    @verbose=true
  when '--help'
    puts USAGE_TEXT  
    exit(0)
  when '--recursive'
    @recursive=true    
  end
end


if ARGV.length == 0
  puts "Missing file argument (try --help)"
  exit 1
end

def get_tid (type,identifier) 
  if identifier.match(/[a-zA-Z]/)
    return identifier
  else
    puts "/usr/bin/getent #{type} #{identifier}" if @debug
    getent_line = %x( /usr/bin/getent #{type} #{identifier} )
    if $? != 0 then
      puts "Problem looking up string id for #{identifier}. Got #{getent_line}"
      exit(1)
    else
      return getent_line.split(':').at(0)
    end
  end
end
def print_acl (path)
  # Use linux tool as-is to display User/group/other permissions and ownership
  # If file is not a PanFS file, then getfacl will display any Posix acls...
  ftype=File.ftype(path)
  if ['file','directory'].include?(ftype)
    standard_perms=%x(/usr/bin/getfacl "#{path}" 2>/dev/null)
    puts "# #{ftype} permissions:"
    puts standard_perms
    curr_acl=%x(/usr/bin/getfattr --only-values -n user.panfs.acl "#{path}" 2>/dev/null)
    
    if $? == 0
      puts curr_acl if @verbose or @debug
      puts "# PanFS ACLs:"
      aclarr=curr_acl.split(" ").drop(1)
      aclarr.map{ |acl| 
        acl.match(/^([+-~])(uid|gid):([[:alnum:]]+),([rwxacdkposCnNDRWPShH]+)(,I:[OICNPD]*)?(?!\*)$/ ) 
      }.compact.sort_by{ |mtc| 
        # list deny acls first, and user acls before group acls
        [mtc[1] != '+' ? 0 : 1, mtc[2] == 'uid' ? 0 : 1]
      }.each do |mtc|
        sense = mtc[1] == '+' ? 'allow: +' : ' deny: -' 
        if mtc[2] == 'uid' 
          type = 'passwd'
          ptype = 'user'
        else
          type = 'group'
          ptype = 'group'    
        end
        next if mtc[3] == "0"
        identifier = get_tid(type,mtc[3])
        aclcomponents = Set.new(mtc[4].to_s.split(''))
        perms=''
        partial=false
        missing=Set.new()
        ['r','w'].each do |p| 
          target_length=@permsinfo[ftype][p]['count']
          target_aclcomps=@permsinfo[ftype][p]['aclcomps']
            
          comparison=( aclcomponents & target_aclcomps ).count
          if comparison == target_length
            perms+=p
          elsif target_length > 1 && comparison > 1
            # File has some directory read permissions but not all
            perms+=p
            partial=true
            missing+=target_aclcomps - ( aclcomponents & target_aclcomps )
          end
  
        end
        if aclcomponents.include?(EXEC)
          perms += 'x'
        end
        inheritance_str=' '
        if ftype == 'directory' && ! mtc[5].nil?
          imtc = mtc[5].match(/^,I:(OI)?(CI)?[IONPID]*/)
          puts mtc[5] + ' ' + imtc.inspect if @debug
          if ! imtc.nil?
            inheritance_str = " inherited_to: #{[imtc[1].nil? ? nil : 'files' , imtc[2].nil? ? nil : 'directories'].join(' ')} "
          end
        end
        partial_str = partial ? ' (PARTIAL; missing ' + missing.to_a.join('') + ')' : ''
        puts sense + ':' + ptype + ":" + identifier + ':' + perms + inheritance_str + partial_str 
        
      end
      
    else
      STDERR.puts "Failure getting ACL for #{path}"
    end
  else
    STDERR.puts "Ignoring #{ftype} at '#{path}'" if @verbose or @debug
  end
end

ARGV.each do |target|
  if @recursive
    Find.find(target) do | path |
      print_acl(path)
    end
  else
    print_acl(target)
  end
end

