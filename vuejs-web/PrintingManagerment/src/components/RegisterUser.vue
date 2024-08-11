<template>
    <form @submit.prevent="submit">
      <v-text-field
        v-model="username.value.value"
        :counter="10"
        :error-messages="username.errorMessage.value"
        label="Username"
      ></v-text-field>

      <v-text-field
        v-model="password.value.value"
        :counter="10"
        :error-messages="password.errorMessage.value"
        label="Password"
      ></v-text-field>

      <v-text-field
        v-model="phone.value.value"
        :counter="7"
        :error-messages="phone.errorMessage.value"
        label="Phone Number"
      ></v-text-field>
  
      <v-text-field
        v-model="email.value.value"
        :error-messages="email.errorMessage.value"
        label="E-mail"
      ></v-text-field>
  
      <v-select
        v-model="select.value.value"
        :error-messages="select.errorMessage.value"
        :items="roles"
        label="Roles"
      ></v-select>
<!--   
      <v-checkbox
        v-model="checkbox.value.value"
        :error-messages="checkbox.errorMessage.value"
        label="Option"
        type="checkbox"
        value="1"
      ></v-checkbox> -->
  
      <v-btn
        class="me-4"
        type="submit"
      >
        submit
      </v-btn>
  
      <v-btn @click="handleReset">
        clear
      </v-btn>
    </form>
  </template>
  <script setup>
    import { ref } from 'vue'
    import { useField, useForm } from 'vee-validate'
  
    const { handleSubmit, handleReset } = useForm({
      validationSchema: {
        username (value) {
          if (value?.length >= 2) return true
  
          return 'Name needs to be at least 2 characters.'
        },
        password (value)
        {
            if (/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/i.test(value)) return true;

            return 'Must be valid password!'
        },
        phone (value) {
          if (value?.length > 9 && /[0-9-]+/.test(value)) return true
  
          return 'Phone number needs to be at least 9 digits.'
        },
        email (value) {
          if (/^[a-z.-]+@[a-z.-]+\.[a-z]+$/i.test(value)) return true
  
          return 'Must be a valid e-mail.'
        },
        select (value) {
          if (value) return true
  
          return 'Select an item.'
        },
        // checkbox (value) {
        //   if (value === '1') return true
  
        //   return 'Must be checked.'
        // },
      },
    })
    const username = useField('username')
    const password = useField('password')
    const phone = useField('phone')
    const email = useField('email')
    const select = useField('select')
    // const checkbox = useField('checkbox')
  
    const roles = ref([
      'Admin',
      'Leader',
      'Deliver',
      'Deginer',
      'Manager',
      'Employee'
    ])
  
    const submit = handleSubmit(values => {
      alert(JSON.stringify(values, null, 2))
    })
  </script>