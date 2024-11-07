import React, { useState } from 'react';
import { StyleSheet, Text, View, TextInput, TouchableOpacity, Alert } from 'react-native';
import { useRoute } from '@react-navigation/native';

const RegisterScreen = ({ navigation }) => {
  const route = useRoute();
  const { babyId } = route.params;
  const [name, setName] = useState('');
  const [mobileNo, setMobileNo] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  
  const [nameError, setNameError] = useState('');
  const [mobileNoError, setMobileNoError] = useState('');
  const [emailError, setEmailError] = useState('');
  const [passwordError, setPasswordError] = useState('');

  // Real-time validation functions
  const handleNameChange = (value) => {
    setName(value);
    setNameError(value.trim() === '' ? 'Name is required' : '');
  };

  const handleMobileNoChange = (value) => {
    setMobileNo(value);
    const mobileRegex = /^[0-9]{10}$/;
    setMobileNoError(!mobileRegex.test(value) ? 'Mobile number must be 10 digits' : '');
  };

  const handleEmailChange = (value) => {
    setEmail(value);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    setEmailError(!emailRegex.test(value) ? 'Please enter a valid email' : '');
  };

  const handlePasswordChange = (value) => {
    setPassword(value);
    setPasswordError(value.length < 6 ? 'Password must be at least 6 characters' : '');
  };

  // Function to send parent data
  const sendCred = () => {
    fetch("http://10.0.2.2:5000/api/parents", {
      method: "POST",
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name,
        mobileNo,
        email,
        password,
 
      })
    })
    .then(res => {
      if (!res.ok) {
        throw new Error('Failed to create parent profile');
      }
      return res.json();
    })
    .then(data => {
      console.log(data);
      Alert.alert('Success', 'Parent details submitted successfully!');
      navigation.navigate('Home'); 
    })
    .catch(error => {
      console.error(error);
      Alert.alert('Error', 'Something went wrong, please try again.');
    });
  };

 
  const handleSignUp = () => {
    if (!name || !mobileNo || !email || !password) {
      Alert.alert('Error', 'Please fill in all fields correctly.');
      return;
    }
    sendCred();
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Care <Text style={styles.highlightedText}>Nest</Text></Text>
      <Text style={styles.subtitle}>Parents Details</Text>

      <TextInput
        style={styles.input}
        placeholder="Name"
        value={name}
        onChangeText={handleNameChange}
        placeholderTextColor="#B0A18C"
      />
      {nameError ? <Text style={styles.errorText}>{nameError}</Text> : null}

      <TextInput
        style={styles.input}
        placeholder="Mobile No."
        value={mobileNo}
        onChangeText={handleMobileNoChange}
        keyboardType="phone-pad"
        placeholderTextColor="#B0A18C"
      />
      {mobileNoError ? <Text style={styles.errorText}>{mobileNoError}</Text> : null}

      <TextInput
        style={styles.input}
        placeholder="Email"
        value={email}
        onChangeText={handleEmailChange}
        keyboardType="email-address"
        placeholderTextColor="#B0A18C"
      />
      {emailError ? <Text style={styles.errorText}>{emailError}</Text> : null}

      <TextInput
        style={styles.input}
        placeholder="Password"
        value={password}
        onChangeText={handlePasswordChange}
        secureTextEntry={true}
        placeholderTextColor="#B0A18C"
      />
      

      {passwordError ? <Text style={styles.errorText}>{passwordError}</Text> : null}

      <TouchableOpacity style={styles.button} onPress={handleSignUp}>
        <Text style={styles.buttonText}>Sign Up</Text>
      </TouchableOpacity>

      <Text style={styles.signInText}>
        Already have an account? <Text style={styles.linkText}>Sign In</Text>
      </Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFF3D6',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
  },
  title: {
    fontSize: 30,
    fontFamily: 'serif',
    color: '#4C3B28',
    marginBottom: 20,
    textAlign: 'center',
  },
  highlightedText: {
    color: '#C17848',
    fontWeight: 'bold',
  },
  subtitle: {
    fontSize: 22,
    marginBottom: 15,
    color: '#4C3B28',
  },
  input: {
    width: '100%',
    height: 55,
    borderColor: '#C17848',
    borderWidth: 2,
    borderRadius: 10,
    paddingHorizontal: 15,
    marginBottom: 20,
    backgroundColor: '#FFF',
    color: '#4C3B28',
    fontSize: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
    elevation: 5,
  },
  button: {
    width: '100%',
    height: 55,
    backgroundColor: '#F4B15E',
    borderRadius: 30,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 20,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
    elevation: 5,
  },
  buttonText: {
    fontSize: 20,
    color: '#FFF',
    fontWeight: 'bold',
  },
  signInText: {
    fontSize: 16,
    color: '#4C3B28',
  },
  linkText: {
    color: '#C17848',
    textDecorationLine: 'underline',
    fontWeight: 'bold',
  },
  errorText: {
    color: 'red',
    fontSize: 12,
    marginBottom: 10,
  },
});

export default RegisterScreen;
