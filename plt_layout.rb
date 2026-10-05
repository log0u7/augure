require "metasm"
elf = Metasm::ELF.decode_file(ARGV[0])
# .plt.sec: 16*i for the i-th JMP_SLOT (in reloc order); .plt: 16*(i+1)
plt_sec = elf.sections.find { |s| s.name.to_s == ".plt.sec" }
plt = elf.sections.find { |s| s.name.to_s == ".plt" }
jmp = elf.relocations.select { |r| r.class.name.include?("Addend") && r.type.to_s.include?("JMP_SLOT") }
jmp.each_with_index do |r, i|
  sym = r.symbol
  puts "#{sym&.name}: got=#{r.offset.to_s(16)} plt.sec=#{(plt_sec.addr.to_i + 16 * i).to_s(16)} plt=#{(plt.addr.to_i + 16 * (i + 1)).to_s(16)}"
end
