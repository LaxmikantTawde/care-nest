import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, Alert } from 'react-native';
import Icon from 'react-native-vector-icons/Ionicons';

const RegisterScreen = ({ navigation }) => {
  const [name, setName] = useState('');
  const [age, setAge] = useState('');
  const [weight, setWeight] = useState('');
  const [height, setHeight] = useState('');
  const [gender, setGender] = useState('');
  const [errors, setErrors] = useState({});

  const validateInputs = () => {
    const newErrors = {};
    if (!name) newErrors.name = 'Name is required';
    if (!age || isNaN(age) || age <= 0) newErrors.age = 'Please enter a valid age';
    if (!weight || isNaN(weight) || weight <= 0) newErrors.weight = 'Please enter a valid weight';
    if (!height || isNaN(height) || height <= 0) newErrors.height = 'Please enter a valid height';
    if (gender.toLowerCase() !== 'boy' && gender.toLowerCase() !== 'girl') 
      newErrors.gender = 'Please enter "boy" or "girl"';
    return newErrors;
  };

  const handleCreateBabyProfile = async () => {
    const validationErrors = validateInputs();
    setErrors(validationErrors);

    if (Object.keys(validationErrors).length > 0) return;

    try {
      const response = await fetch("http://10.0.2.2:5000/api/babies", {
        method: "POST",
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name,
          age,
          weight,
          height,
          gender
        })
      });

      const data = await response.json();
      if (response.ok) { 
        console.log(data);
        Alert.alert('Success', 'Baby details submitted successfully!');
        
        
        navigation.navigate('Parent', { babyId: data._id });
      } else {
        Alert.alert('Error', data.message || 'Something went wrong, please try again.');
      }
    } catch (error) {
      console.error(error);
      Alert.alert('Error', 'Something went wrong, please try again.');
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Care <Text style={styles.highlightedText}>Nest</Text></Text>
      <Text style={styles.subtitle}>Baby Details</Text>

      <View style={styles.inputContainer}>
        <Icon name="person-outline" size={24} color="#C17848" />
        <TextInput
          style={styles.input}
          placeholder="Name"
          onChangeText={setName}
          value={name}
          placeholderTextColor="#B0A18C"
        />
      </View>
      {errors.name && <Text style={styles.errorText}>{errors.name}</Text>}

      <View style={styles.inputContainer}>
        <Icon name="calendar-outline" size={24} color="#C17848" />
        <TextInput
          style={styles.input}
          placeholder="Age(months)"
          onChangeText={setAge}
          value={age}
          placeholderTextColor="#B0A18C"
          keyboardType="numeric"
        />
      </View>
      {errors.age && <Text style={styles.errorText}>{errors.age}</Text>}

      <View style={styles.inputContainer}>
        <Icon name="fitness-outline" size={24} color="#C17848" />
        <TextInput
          style={styles.input}
          placeholder="Weight(kg)"
          onChangeText={setWeight}
          value={weight}
          placeholderTextColor="#B0A18C"
          keyboardType="numeric"
        />
      </View>
      {errors.weight && <Text style={styles.errorText}>{errors.weight}</Text>}

      <View style={styles.inputContainer}>
        <Icon name="ribbon-outline" size={24} color="#C17848" />
        <TextInput
          style={styles.input}
          placeholder="Height(cm)"
          onChangeText={setHeight}
          value={height}
          placeholderTextColor="#B0A18C"
          keyboardType="numeric"
        />
      </View>
      {errors.height && <Text style={styles.errorText}>{errors.height}</Text>}

      <View style={styles.inputContainer}>
        <Icon name="male-female-outline" size={24} color="#C17848" />
        <TextInput
          style={styles.input}
          placeholder="Gender (boy/girl)"
          onChangeText={setGender}
          value={gender}
          placeholderTextColor="#B0A18C"
        />
      </View>
      {errors.gender && <Text style={styles.errorText}>{errors.gender}</Text>}

      <TouchableOpacity style={styles.button} onPress={handleCreateBabyProfile}>
        <Text style={styles.buttonText}>Add</Text>
      </TouchableOpacity>

      <Text style={styles.newUserText}>
        Already have an account?{' '}
        <Text
          style={styles.linkText}
          onPress={() => navigation.navigate('SignIn')}
        >
          Sign In
        </Text>
      </Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    justifyContent: 'center',
    backgroundColor: '#fff',
  },
  title: {
    fontSize: 32,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 20,
  },
  highlightedText: {
    color: '#C17848',
  },
  subtitle: {
    fontSize: 20,
    textAlign: 'center',
    marginBottom: 20,
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    borderBottomWidth: 1,
    borderBottomColor: '#C17848',
    marginBottom: 15,
  },
  input: {
    flex: 1,
    padding: 10,
    fontSize: 18,
    color: '#333',
  },
  button: {
    backgroundColor: '#C17848',
    padding: 15,
    alignItems: 'center',
    borderRadius: 5,
    marginTop: 20,
  },
  buttonText: {
    color: '#fff',
    fontSize: 18,
  },
  errorText: {
    color: 'red',
    marginTop: 5,
  },
  newUserText: {
    textAlign: 'center',
    marginTop: 20,
  },
  linkText: {
    color: '#C17848',
    fontWeight: 'bold',
  },
});

export default RegisterScreen;
