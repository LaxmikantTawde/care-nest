import React from 'react';
import { View, Text, TextInput, Image, ScrollView, StyleSheet, TouchableOpacity } from 'react-native';

const dishes = [
  { name: 'Appam', description: 'Tiffin Friendly, Energy Booster + 2 more.', image: 'https://images.unsplash.com/photo-1646398123647-695431536f7c?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxzZWFyY2h8MXx8YXBwYW18ZW58MHx8MHx8fDA%3D', tags: ['⏲️ 15 Mins', '🌾 Grains', '🍇 Pulses'] },
  { name: 'Biryani', description: 'Spicy and Flavorful Rice Dish', image: 'https://images.unsplash.com/photo-1505253758473-96b7015fcd40?w=500&auto=format&fit=crop&q=60&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxzZWFyY2h8NHx8YmlyeWFuaXxlbnwwfHwwfHx8MA%3D%3D', tags: ['⏲️ 30 Mins', '🍚 Rice', '🍗 Chicken'] },
  { name: 'Pasta', description: 'Delicious Italian Pasta', image: 'https://i.imgur.com/yzfzSWj.jpg', tags: ['⏲️ 20 Mins', '🍝 Pasta', '🍅 Tomato'] },
  { name: 'Salad', description: 'Fresh and Healthy Salad', image: 'https://i.imgur.com/7e9A0PS.jpg', tags: ['⏲️ 10 Mins', '🥗 Greens', '🥒 Vegetables'] },
  { name: 'Fried Rice', description: 'Stir-Fried Rice with Vegetables', image: 'https://i.imgur.com/3FeP2ZZ.jpg', tags: ['⏲️ 25 Mins', '🍚 Rice', '🥕 Vegetables'] },
  { name: 'Pancakes', description: 'Fluffy Breakfast Pancakes', image: 'https://i.imgur.com/X1S2V7L.jpg', tags: ['⏲️ 15 Mins', '🥞 Breakfast', '🍯 Syrup'] },
  { name: 'Sushi', description: 'Japanese Sushi Rolls', image: 'https://i.imgur.com/T4sQUrG.jpg', tags: ['⏲️ 30 Mins', '🍣 Seafood', '🍚 Rice'] },
  { name: 'Tacos', description: 'Spicy Mexican Tacos', image: 'https://i.imgur.com/AXTG9Vv.jpg', tags: ['⏲️ 20 Mins', '🌮 Tortilla', '🍖 Meat'] },
  { name: 'Chili', description: 'Hearty Chili with Beans', image: 'https://i.imgur.com/OFGaBxd.jpg', tags: ['⏲️ 40 Mins', '🌶️ Spicy', '🥩 Beef'] },
  { name: 'Omelette', description: 'Classic Breakfast Omelette', image: 'https://i.imgur.com/yIaS1Be.jpg', tags: ['⏲️ 10 Mins', '🍳 Eggs', '🧀 Cheese'] },
  { name: 'Curry', description: 'Flavorful Chicken Curry', image: 'https://i.imgur.com/3bRf3B7.jpg', tags: ['⏲️ 35 Mins', '🍗 Chicken', '🍛 Spicy'] },
  { name: 'Ramen', description: 'Delicious Japanese Ramen', image: 'https://i.imgur.com/KD4w6yB.jpg', tags: ['⏲️ 25 Mins', '🍜 Noodles', '🥢 Soup'] },
  { name: 'Smoothie', description: 'Healthy Fruit Smoothie', image: 'https://i.imgur.com/KIWJHbQ.jpg', tags: ['⏲️ 5 Mins', '🍓 Fruits', '🥛 Dairy'] },
  { name: 'Quiche', description: 'Savory French Quiche', image: 'https://i.imgur.com/JBZmfHR.jpg', tags: ['⏲️ 40 Mins', '🥧 Pie', '🍳 Eggs'] },
  { name: 'Sandwich', description: 'Classic Ham Sandwich', image: 'https://i.imgur.com/8QuovOy.jpg', tags: ['⏲️ 10 Mins', '🍞 Bread', '🥬 Lettuce'] },
  { name: 'Crepes', description: 'Thin French Crepes', image: 'https://i.imgur.com/NLk9LZT.jpg', tags: ['⏲️ 20 Mins', '🥞 Dessert', '🍓 Fruits'] },
  { name: 'Lasagna', description: 'Layered Italian Lasagna', image: 'https://i.imgur.com/MJXoPQa.jpg', tags: ['⏲️ 50 Mins', '🍝 Pasta', '🧀 Cheese'] },
  { name: 'Meatballs', description: 'Savory Meatballs in Sauce', image: 'https://i.imgur.com/Ht8pFRQ.jpg', tags: ['⏲️ 30 Mins', '🍖 Meat', '🍝 Pasta'] },
  { name: 'Hummus', description: 'Creamy Chickpea Dip', image: 'https://i.imgur.com/92Bgvkc.jpg', tags: ['⏲️ 10 Mins', '🥙 Dip', '🥒 Vegetables'] },
  { name: 'Chocolate Cake', description: 'Rich Chocolate Cake', image: 'https://i.imgur.com/P8Fr6jl.jpg', tags: ['⏲️ 60 Mins', '🍰 Dessert', '🍫 Chocolate'] },
];

const MealListScreen = ({ navigation }) => {
  return (
    <View style={styles.container}>
      {/* Search Bar */}
      <View style={styles.searchBar}>
        <TextInput
          style={styles.searchInput}
          placeholder="Search"
          placeholderTextColor="#888"
        />
        <TouchableOpacity>
          <Text style={styles.searchIcon}>🔍</Text>
        </TouchableOpacity>
      </View>

      {/* Scrollable Meal List */}
      <ScrollView contentContainerStyle={styles.scrollContainer}>
        {dishes.map((dish, index) => (
          <TouchableOpacity
            key={index}
            style={styles.mealCard}
            onPress={() => navigation.navigate('recipe', { dish })}
          >
            <Image
              source={{ uri: dish.image }} // Use the image URL from the dish object
              style={styles.mealImage}
              resizeMode="cover"
            />
            <View style={styles.mealInfo}>
              <Text style={styles.mealName}>{dish.name}</Text>
              <Text style={styles.mealDescription}>{dish.description}</Text>
              <View style={styles.mealTags}>
                {dish.tags.map((tag, tagIndex) => (
                  <Text key={tagIndex} style={styles.tagText}>{tag}</Text>
                ))}
              </View>
            </View>
          </TouchableOpacity>
        ))}
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFFEFF',
    paddingHorizontal: 16,
  },
  searchBar: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#E9E9F0',
    borderRadius: 25,
    paddingVertical: 10,
    paddingHorizontal: 15,
    marginVertical: 20,
    elevation: 2,
  },
  searchInput: {
    flex: 1,
    fontSize: 16,
    color: '#333',
  },
  searchIcon: {
    fontSize: 20,
    marginLeft: 10,
    color: '#333',
  },
  scrollContainer: {
    paddingBottom: 20,
  },
  mealCard: {
    flexDirection: 'row',
    backgroundColor: '#FFFFE0',
    padding: 15,
    borderRadius: 15,
    marginBottom: 15,
    alignItems: 'center',
    elevation: 3,
  },
  mealImage: {
    width: 70,
    height: 70,
    borderRadius: 10,
    marginRight: 10,
    borderWidth: 1,
    borderColor: '#ccc',
  },
  mealInfo: {
    flex: 1,
  },
  mealName: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#333',
  },
  mealDescription: {
    fontSize: 14,
    color: '#7B7B7B',
    marginBottom: 5,
  },
  mealTags: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 5,
  },
  tagText: {
    fontSize: 12,
    color: '#555',
  },
});

export default MealListScreen;
